type HostString;
fn HostString::utf16words(self: HostString) -> Int = "hoststring" "utf16words"
fn HostString::fillmem(self: HostString, hostmem: MoonMem) -> Int = "hoststring" "fillmem"
fn HostString::get(self: HostString) -> String {
  let len_bytes = self.utf16words() * 2
  let bytes = Bytes::make(len_bytes, 255)
  let mem = MoonMem::new(bytes)
  let _ = self.fillmem(mem)
  bytes.to_string()
}

type MoonMem;
fn MoonMem::new(in: Bytes) -> MoonMem = "%string_to_jsstring"

fn init {}

fn main {}

pub fn http_entrypoint(path: HostString) -> MoonMem {
  let path = path.get()
  let body = Buffer::make(256)
  body.write_string("🐰MoonBit 和 ⚙️Rust 让访问 ")
  body.write_string(path)
  body.write_string(" 的开发者🛠️再次伟大\r\n")
  MoonMem::new(body.to_bytes())
}
