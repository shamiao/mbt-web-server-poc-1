use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, Request, Response};
use std::sync::Arc;
use std::sync::OnceLock;

struct GlobalData {
    pub module: wasmtime::Module,
    pub linker: wasmtime::Linker<()>,
}

struct MoonMem(pub usize, pub usize);
struct HostString(pub String);

impl HostString {
    pub fn utf16_words(&self) -> usize {
        self.0.chars().map(|c| c.len_utf16()).sum()
    }

    pub fn fill_mem(&self, mem: &mut [u8]) -> anyhow::Result<()> {
        if mem.len() < (self.utf16_words() * 2) {
            return Err(anyhow::anyhow!("insufficient memory"));
        }
        let mut ptr = 0usize;
        for utf16_word in self.0.encode_utf16() {
            mem[ptr] = (utf16_word & 0x00ffu16) as u8;
            mem[ptr + 1] = ((utf16_word & 0xff00u16) >> 8) as u8;
            ptr += 2;
        }
        Ok(())
    }
}

static APP: OnceLock<GlobalData> = OnceLock::new();

async fn handler(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    use http_body_util::BodyExt;
    use wasmtime::{ExternRef, Rooted};
    use hyper::header::{HeaderValue, CONTENT_TYPE};
    let app = APP.get().unwrap();

    let mut store = wasmtime::Store::new(app.module.engine(), ());
    let inst = app.linker.instantiate(&mut store, &app.module)?;

    // moonbit fn init
    let fn_start = inst.get_typed_func::<(), ()>(&mut store, "_start")?;
    fn_start.call(&mut store, ())?;

    // moonbit param 1 externref, path in uri
    let hs_path = HostString(req.uri().path().to_string());
    let hs_extref = ExternRef::new(&mut store, Arc::new(hs_path))?;

    // moonbit func `http_entrypoint`
    let fn_entrypoint = inst.get_typed_func::<(Rooted<ExternRef>,), (Option<Rooted<ExternRef>>,)>(
        &mut store,
        "http_entrypoint",
    )?;
    let (ret_extern,) = fn_entrypoint.call(&mut store, (hs_extref,))?;

    // moonbit result externref, result body bytes encoded in utf-16
    let ret_moonmem = ret_extern
        .unwrap()
        .data(&mut store)?
        .downcast_ref::<MoonMem>()
        .unwrap();
    let (offset, length) = (ret_moonmem.0, ret_moonmem.1);

    // wasm memory `moonbit.memory`, load actual bytes content
    let mem = inst.get_memory(&mut store, "moonbit.memory").unwrap();
    let mem_slice = &mem.data(&mut store)[(offset)..(offset + length)];

    // convert to utf-8 string
    let vec_u16 = mem_slice
        .chunks_exact(2)
        .map(|chunk| { (chunk[0] as u16) | ((chunk[1] as u16) << 8) })
        .collect::<Vec<_>>();
    let body_str = String::from_utf16(&vec_u16)?;
    let body_bytes_v: bytes::Bytes = body_str.into_bytes().into();

    // return http body
    let rsp_body =
        http_body_util::Full::new(body_bytes_v)
            .map_err(|_| anyhow!("unreachable"))
            .boxed();
    let mut rsp = hyper::Response::new(rsp_body);
    rsp.headers_mut().append(CONTENT_TYPE, HeaderValue::from_str("text/plain;charset=utf-8")?);
    Ok(rsp)
}

fn init_wasm(wasm_path: String) -> Result<()> {
    use wasmtime::*;
    let engine = Engine::default();
    let module = Module::from_file(&engine, &wasm_path)?;
    let mut linker = Linker::<()>::new(&engine);

    // import: "spectest" module
    linker.func_wrap("spectest", "print_i32", |x: i32| {
        print!("{}", x);
    })?;
    linker.func_wrap("spectest", "print_f64", |x: f64| {
        print!("{}", x);
    })?;
    linker.func_wrap("spectest", "print_char", |x: i32| {
        if let Some(ch) = char::from_u32(x as u32) {
            print!("{}", ch);
        }
    })?;

    // import: "js_string", "moonmem" and "hoststring" modules
    unsafe {
        // UNSAFE:
        // wasmtime `func_new` and similar functions panic when processing `externref`
        // params or result values. Have to use `func_new_unchecked` as a workaround.
        // (see https://github.com/bytecodealliance/wasmtime/issues/8432)

        linker.func_new_unchecked(
            "js_string",
            "new",
            FuncType::new(&engine, [ValType::I32, ValType::I32], [ValType::EXTERNREF]),
            |mut caller, space: &mut [ValRaw]| -> Result<()> {
                let param1 = Val::from_raw(&mut caller, space[0], ValType::I32);
                let param2 = Val::from_raw(&mut caller, space[1], ValType::I32);
                assert!(param1.ty(&mut caller).is_i32() && param2.ty(&mut caller).is_i32());

                let (offset, wordlen) = (param1.unwrap_i32() as usize, param2.unwrap_i32());
                let bytelen = wordlen as usize * 2;

                let mem = caller.get_export("moonbit.memory").unwrap();
                let mem = mem.into_memory().unwrap();
                let mut buffer = bytes::BytesMut::with_capacity(bytelen);
                buffer.resize(bytelen, 0);
                let buf_view = buffer.as_mut();

                mem.read(&mut caller, offset, &mut buf_view[0..bytelen])?;

                let ret = ExternRef::new(&mut caller, MoonMem(offset, bytelen))?;

                let ret_raw = ValRaw::externref(ret.to_raw(&mut caller)?);
                space[0] = ret_raw;
                Ok(())
            },
        )?;

        linker.func_new_unchecked(
            "hoststring",
            "utf16words",
            FuncType::new(&engine, [ValType::EXTERNREF], [ValType::I32]),
            |mut caller, space: &mut [ValRaw]| -> Result<()> {
                let param1 = Val::from_raw(caller.as_context_mut(), space[0], ValType::EXTERNREF);
                assert!(param1.ty(&mut caller).is_externref());
                let externref = param1.unwrap_externref();
                let hs = externref
                    .unwrap()
                    .data(&mut caller)?
                    .downcast_ref::<Arc<HostString>>()
                    .unwrap();
                let ret_raw = ValRaw::i32(hs.utf16_words() as i32);
                space[0] = ret_raw;
                Ok(())
            },
        )?;

        linker.func_new_unchecked(
            "hoststring",
            "fillmem",
            FuncType::new(
                &engine,
                [ValType::EXTERNREF, ValType::EXTERNREF],
                [ValType::I32],
            ),
            |mut caller, space: &mut [ValRaw]| -> Result<()> {
                let param1 = Val::from_raw(&mut caller, space[0], ValType::EXTERNREF);
                let param2 = Val::from_raw(&mut caller, space[1], ValType::EXTERNREF);
                assert!(param1.ty(&mut caller).is_externref() && param2.ty(&mut caller).is_externref());

                let hs_extern = param1.unwrap_externref();
                let hs = hs_extern
                    .unwrap()
                    .data(&caller)?
                    .downcast_ref::<Arc<HostString>>()
                    .unwrap();
                let hs = hs.clone();
                let mm_extern = param2.unwrap_externref();
                let mm = mm_extern
                    .unwrap()
                    .data(&caller)?
                    .downcast_ref::<MoonMem>()
                    .unwrap();
                let (offset, length) = (mm.0, mm.1);

                let mem = caller.get_export("moonbit.memory").unwrap();
                let mem = mem.into_memory().unwrap();
                let mem = mem.data_mut(&mut caller);
                hs.fill_mem(&mut mem[offset..(offset + length)])?;

                let ret_raw = ValRaw::i32(0 as i32);
                space[0] = ret_raw;
                Ok(())
            },
        )?;
    }

    APP.set(GlobalData { module, linker })
        .map_err(|_| anyhow!("duplicate init"))?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let argv = std::env::args().collect::<Vec<_>>();
    if argv.len() < 2 {
        println!("usage: server-runtime [wasm-file-path]");
        std::process::exit(1);
    }

    init_wasm(argv[1].clone())?;

    let listen_ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
    let listen_addr = std::net::SocketAddr::from((listen_ip, 8000));
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("accepting connection from {}", &addr);
                let io = hyper_util::rt::TokioIo::new(stream);
                tokio::task::spawn(async move {
                    let service = hyper::service::service_fn(handler);
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .serve_connection(io, service)
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
            Err(err) => {
                eprintln!("error accepting incoming connection: {}", &err);
            }
        }
    }
}
