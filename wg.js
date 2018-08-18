const execFile = require('child_process').execFile;
const tmp = require('tmp');
const fs = require('fs');

async function execAsync(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, (error, stdout, stderr) => {
      if (error) {
        reject(error)
      } else {
        resolve(stdout)
      }
    })
  })
}

class Wg {
  constructor(iface) {
    this.iface = iface;
  }

  async up(addr) {
    let wg = this
    await execAsync("ip", ["link", "add", wg.iface, "type", "wireguard"])
    await execAsync("ip", ["link", "set", "mtu", "1420", "dev", wg.iface])
    await execAsync("ip", ["addr", "add", addr, "dev", wg.iface])
    await execAsync("ip", ["link", "set", wg.iface, "up"])
    // await execAsync("ip", ["route", "add", "10.13.37.0/24", "dev", wg.iface])
  }

  async down() {
    let wg = this
    await execAsync("ip", ["link", "del", "dev", wg.iface])
  }

  async getPeersConfig() {
    let wg = this

    let stdout = await execAsync("wg", ["showconf", wg.iface])

    return stdout.toString('utf8')
      .split("\n")
      .filter((line) => {
        return !line.trim().startsWith("[Interface]")
          && !line.trim().startsWith("ListenPort")
          && !line.trim().startsWith("FwMark")
          && !line.trim().startsWith("PrivateKey")
          && line !== ""
      })
      .join("\n")
  }

  /**
   *
   * @param {Object} peer - The new peer's information
   * @param {string} peer.pubkey - The public key
   * @param {string} peer.allowedIPs - The peer's allowed IPs
   */
  async addPeer(peer) {
    let wg = this
    await execAsync("wg", ["set", wg.iface, "peer", peer.pubkey, "allowed-ips", peer.allowedIPs])
  }

  async addConfig(configString) {
    let wg = this;
    return new Promise((resolve, reject) => {
      tmp.file((err, path, fd, cleanup) => {
        if (err) {
          reject(err);
          return;
        }

        fs.write(fd, configString, async (err) => {
          if (err) {
            reject(err);
            return;
          }

          await execAsync("wg", ["addconf", wg.iface, path])
          cleanup()
          resolve()
        });
      });
    });
  }
}

module.exports = Wg;