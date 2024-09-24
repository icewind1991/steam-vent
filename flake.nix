{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-24.05";
    flakelight = {
      url = "github:nix-community/flakelight";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mill-scale = {
      url = "github:icewind1991/mill-scale";
      inputs.flakelight.follows = "flakelight";
    };
  };
  outputs = { mill-scale, ... }: mill-scale ./. {
    extraFiles = [ "system.pem" ];
    packages = {
      proto-builder = { craneLib, ... }: craneLib.buildPackage {
        src = craneLib.cleanCargoSource ./protobuf/build;
        doCheck = false;
        strictDeps = true;
      };
    };
  };
}
