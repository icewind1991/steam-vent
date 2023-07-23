{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-23.05";
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
      src = lib.sources.sourceByRegex (lib.cleanSource ./.) ["Cargo.*" "(src|derive|benches|tests|examples|crypto|protobuf)(/.*)?"];
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
      };

      devShells.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs;
          [
            rustc
            cargo
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
