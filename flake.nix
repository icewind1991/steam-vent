{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-23.11";
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.inputs.flake-utils.follows = "utils";
  };

  outputs = {
    self,
    nixpkgs,
    utils,
    naersk,
    rust-overlay,
  }:
    utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = (import nixpkgs) {
        inherit system overlays;
      };
      lib = pkgs.lib;
      naersk' = pkgs.callPackage naersk {};
      srcFilters = ["Cargo.*" "(src|derive|benches|tests|examples|crypto|protobuf)(/.*)?"];
      src = lib.sources.sourceByRegex ./. srcFilters;
      buildDeps = with pkgs; [
        pkg-config
        openssl
      ];
      nearskOpt = {
        inherit src;
        pname = "steam-vent";
        nativeBuildInputs = buildDeps;
      };
    in rec {
      packages = {
        check = naersk'.buildPackage (nearskOpt
          // {
            mode = "check";
          });
        clippy = naersk'.buildPackage (nearskOpt
          // {
            mode = "clippy";
          });
        test = naersk'.buildPackage (nearskOpt
          // {
            release = false;
            mode = "test";
          });
        test-crypto = naersk'.buildPackage (nearskOpt
          // {
            release = false;
            mode = "test";
            cargoTestOptions = x: x ++ ["-p" "steam-vent-crypto"];
          });
        proto-builder = naersk'.buildPackage {
          src = lib.sources.sourceByRegex ./protobuf/build srcFilters;
        };
      };

      devShells.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs;
          [
            rust-bin.stable.latest.default
            bacon
            cargo-edit
            cargo-outdated
            clippy
            cargo-audit
            cargo-msrv
            cargo-fuzz
          ]
          ++ buildDeps;
      };
    });
}
