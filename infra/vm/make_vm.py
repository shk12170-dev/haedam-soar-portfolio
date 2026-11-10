"""Ubuntu 24.04 Server VM을 무인 설치(autoinstall)로 만든다(1인 재구성에서 새로 작성).

팀은 포털 VM(A)과 DB VM(B)을 VMware에서 손으로 설치했다. 한 PC 재구성에서는 같은 OS·주소로
README만 보고 다시 만들 수 있게, cloud-init(NoCloud) 시드 ISO와 .vmx를 만들어 설치를 자동화한다.

사용:
    python infra/vm/make_vm.py portal --vms-dir C:/aleph-capstone/vms --iso <ubuntu.iso> --pubkey <키.pub>
    python infra/vm/make_vm.py db ...
로그인은 SSH 키로만 한다(allow-pw: false). 콘솔용 비밀번호는 무작위로 만들어 vms-dir에만 저장한다.
"""
from __future__ import annotations

import argparse
import io
import secrets
import subprocess
from pathlib import Path

import pycdlib
import yaml

VMWARE = Path(r"C:\Program Files\VMware\VMware Workstation")

# NIC: (vmx 이름, VMware 망, 고정 MAC, netplan 설정)
SPECS = {
    "portal": {
        "hostname": "haedam-portal", "mem": 2048, "cpus": 2, "disk": "20GB", "vnc": 5902,
        "nics": [
            ("VMnet8", "00:50:56:2a:00:11", {"dhcp4": True}),  # 설치·패키지용 NAT (팀 A VM과 같음)
            ("VMnet7", "00:50:56:2a:00:12", {"addresses": ["10.10.30.20/24"]}),  # pfSense OpenVPN 접속용
        ],
    },
    "db": {
        "hostname": "haedam-db", "mem": 2048, "cpus": 2, "disk": "20GB", "vnc": 5903,
        "nics": [
            ("VMnet8", "00:50:56:2a:00:21", {"dhcp4": True, "dhcp4-overrides": {"route-metric": 200}}),
            ("VMnet4", "00:50:56:2a:00:22", {"addresses": ["10.10.20.10/24"],
                                             "routes": [{"to": "10.250.0.0/24", "via": "10.10.20.1"}]}),
        ],
    },
}


def user_data(spec: dict, pubkey: str, pw_hash: str) -> str:
    eths = {}
    for i, (_, mac, cfg) in enumerate(spec["nics"]):
        eths[f"nic{i}"] = {"match": {"macaddress": mac}, "set-name": f"nic{i}", **cfg}
    doc = {"autoinstall": {
        "version": 1,
        "locale": "en_US.UTF-8",
        "keyboard": {"layout": "us"},
        "timezone": "Asia/Seoul",
        "refresh-installer": {"update": False},
        "identity": {"hostname": spec["hostname"], "username": "haedam", "password": pw_hash},
        "ssh": {"install-server": True, "allow-pw": False, "authorized-keys": [pubkey]},
        "network": {"version": 2, "ethernets": eths},
        "storage": {"layout": {"name": "direct"}},
        "packages": ["python3-venv", "python3-pip", "curl", "openvpn", "jq"],
        "late-commands": [
            "echo 'haedam ALL=(ALL) NOPASSWD:ALL' > /target/etc/sudoers.d/90-haedam",
            "chmod 440 /target/etc/sudoers.d/90-haedam",
        ],
        "shutdown": "reboot",
    }}
    return "#cloud-config\n" + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def seed_iso(path: Path, ud: str, hostname: str) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="CIDATA")
    for name, body in (("user-data", ud), ("meta-data", f"instance-id: {hostname}\nlocal-hostname: {hostname}\n")):
        data = body.encode()
        iso.add_fp(io.BytesIO(data), len(data), f"/{name.replace('-', '').upper()[:8]}.;1",
                   rr_name=name, joliet_path=f"/{name}")
    iso.write(str(path))
    iso.close()


def vmx(name: str, spec: dict, iso: str, seed: Path, vnc_pw: str) -> str:
    lines = [
        '.encoding = "UTF-8"', 'config.version = "8"', 'virtualHW.version = "21"',
        f'displayName = "{spec["hostname"]}"', 'guestOS = "ubuntu-64"', 'firmware = "efi"',
        f'memsize = "{spec["mem"]}"', f'numvcpus = "{spec["cpus"]}"',
        'scsi0.present = "TRUE"', 'scsi0.virtualDev = "pvscsi"',
        'scsi0:0.present = "TRUE"', f'scsi0:0.fileName = "{name}.vmdk"',
        'sata0.present = "TRUE"',
        'sata0:0.present = "TRUE"', 'sata0:0.deviceType = "cdrom-image"', f'sata0:0.fileName = "{iso}"',
        'sata0:1.present = "TRUE"', 'sata0:1.deviceType = "cdrom-image"', f'sata0:1.fileName = "{seed}"',
        'pciBridge0.present = "TRUE"', 'pciBridge4.present = "TRUE"', 'pciBridge4.virtualDev = "pcieRootPort"',
        'pciBridge4.functions = "8"', 'rtc.diffFromUTC = "0"', 'tools.syncTime = "TRUE"',
        'RemoteDisplay.vnc.enabled = "TRUE"', f'RemoteDisplay.vnc.port = "{spec["vnc"]}"',
        f'RemoteDisplay.vnc.password = "{vnc_pw}"',
    ]
    for i, (net, mac, _) in enumerate(spec["nics"]):
        conn = "nat" if net == "VMnet8" else "custom"
        lines += [f'ethernet{i}.present = "TRUE"', f'ethernet{i}.virtualDev = "vmxnet3"',
                  f'ethernet{i}.connectionType = "{conn}"', f'ethernet{i}.addressType = "static"',
                  f'ethernet{i}.address = "{mac}"', f'ethernet{i}.pciSlotNumber = "{160 + i * 32}"']
        if conn == "custom":
            lines.append(f'ethernet{i}.vnet = "{net}"')
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=sorted(SPECS))
    ap.add_argument("--vms-dir", required=True)
    ap.add_argument("--iso", required=True)
    ap.add_argument("--pubkey", required=True)
    a = ap.parse_args()
    spec = SPECS[a.role]
    d = Path(a.vms_dir) / spec["hostname"]
    d.mkdir(parents=True, exist_ok=True)
    pw = secrets.token_urlsafe(15)
    (d / "console-password.txt").write_text(pw + "\n", encoding="utf-8")
    pw_hash = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=pw, capture_output=True,
                             text=True, check=True).stdout.strip()
    vnc_pw = secrets.token_urlsafe(6)[:8]
    (d / "vnc.pass").write_text(vnc_pw + "\n", encoding="utf-8")
    pub = Path(a.pubkey).read_text(encoding="utf-8").strip()
    seed = d / "seed.iso"
    seed_iso(seed, user_data(spec, pub, pw_hash), spec["hostname"])
    name = spec["hostname"]
    if not (d / f"{name}.vmdk").exists():
        subprocess.run([str(VMWARE / "vmware-vdiskmanager.exe"), "-c", "-s", spec["disk"], "-a", "pvscsi",
                        "-t", "1", str(d / f"{name}.vmdk")], check=True, capture_output=True)
    (d / f"{name}.vmx").write_text(vmx(name, spec, a.iso, seed, vnc_pw), encoding="utf-8")
    print(d / f"{name}.vmx")


if __name__ == "__main__":
    main()
