# nixpkgs nixos-25.11 at b6018f87da91d19d0ab4cf979885689b469cdd41 (cargo 1.91.1).
{ pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/b6018f87da91d19d0ab4cf979885689b469cdd41.tar.gz";
    sha256 = "0ln4yw7z3g9lb0x081hc0pd2j1wsx2qqf6bgmwwvdbkcl4bcy1dp";
  }) { } }:
pkgs.mkShell {
  packages = with pkgs; [ cargo rustc clippy rustfmt gcc ];
}
