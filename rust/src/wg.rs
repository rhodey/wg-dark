use failure::Error;
use std::net::IpAddr;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use pnetlink::packet::route::link::Links;
use pnetlink::packet::route::link::IfInfoPacketBuilder;
use pnetlink::packet::route::link::{RTM_NEWLINK, IFLA_INFO_KIND, IFLA_LINKINFO, IFLA_IFNAME};
use pnetlink::packet::route::RtAttrPacket;
use pnetlink::packet::route::addr::Addresses;
use pnetlink::packet::route::addr::Scope;
use pnetlink::packet::route::route::WithPayload;
use pnetlink::packet::netlink::NetlinkConnection;
use pnetlink::packet::netlink::NetlinkRequestBuilder;
use pnetlink::packet::netlink::NetlinkReader;
use pnetlink::packet::netlink::NetlinkMsgFlags;
use pnet_macros_support::packet::Packet;

#[derive(Debug, Clone)]
pub struct Wg {
  pub iface: String
}

#[derive(Debug)]
pub struct Keypair {
  pub privkey: String,
  pub pubkey: String
}

fn run(cmd: &str, args: &[&str], input: Option<&str>) -> Result<String, Error> {
  debug!("$ {} {}", cmd, args.join(" "));
  let mut child = Command::new(cmd)
    .args(args)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .spawn()?;

  if let Some(input) = input {
      let mut stdin = child.stdin.as_mut().expect("Failed to open stdin");
      stdin.write_all(input.as_bytes()).expect("Failed to write to stdin");
  }

  let output = child.wait_with_output()?;

  if !output.status.success() {
    bail!("command failed")
  }

  Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
impl Wg {
  pub fn new(iface: &str) -> Wg {
    Wg { iface: iface.to_string() }
  }

  pub fn generate_keypair() -> Result<Keypair, Error> {
    let privkey = run("wg", &["genkey"], None)?;
    let pubkey  = run("wg", &["pubkey"], Some(&privkey))?;

    Ok(Keypair { privkey, pubkey })
  }

  pub fn add_link(&self) -> Result<(), Error> {
    let mut conn = NetlinkConnection::new();
    let ifi = {
        IfInfoPacketBuilder::new().
            append(RtAttrPacket::create_with_payload(IFLA_IFNAME, &self.iface[..])).
            append(RtAttrPacket::create_with_payload(
                IFLA_LINKINFO, RtAttrPacket::create_with_payload(IFLA_INFO_KIND, "wireguard"))).build()
    };
    let req = NetlinkRequestBuilder::new(RTM_NEWLINK, NetlinkMsgFlags::NLM_F_CREATE | NetlinkMsgFlags::NLM_F_EXCL | NetlinkMsgFlags::NLM_F_ACK)
        .append(ifi).build();
    try!(conn.write(req.packet()));
    let reader = NetlinkReader::new(conn);
    Ok(reader.read_to_end()?)
  }

  pub fn add_address(&self, address: &str) -> Result<(), Error> {
    let address_pieces = address.split('/').collect::<Vec<&str>>();
    let mut conn = NetlinkConnection::new();
    let link = conn.get_link_by_name(&self.iface).unwrap().unwrap();
    Ok(conn.add_addr(&link,
      address_pieces[0].parse::<IpAddr>().unwrap(),
      None,
      Scope::Site,
      address_pieces[1].parse::<u8>().unwrap())?)
  }

  pub fn link_up(&self) -> Result<(), Error> {
    let mut conn = NetlinkConnection::new();
    let link = conn.get_link_by_name(&self.iface).unwrap().unwrap();
    Ok(conn.link_set_up(link.get_index())?)
  }

  pub fn up(&self, privkey: &str, address: &str) -> Result<(), Error> {
    self.add_link()?;
    self.add_address(address)?;
    self.link_up()?;
    let _ = run("ip", &["route", "add", "10.13.37.0/24", "dev", &self.iface], None);

    self.add_config(&format!("[Interface]\nPrivateKey = {}\nListenPort = 1337", privkey))?;

    Ok(())
  }

  pub fn down(&self) -> Result<(), Error> {
    run("ip", &["link", "del", "dev", &self.iface], None)?;

    Ok(())
  }

  pub fn add_config(&self, config: &str) -> Result<(), Error> {
    run("wg", &["addconf", &self.iface, "/dev/stdin"], Some(config))?;

    Ok(())
  }
}