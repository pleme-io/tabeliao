{
  description = "tabeliao — publisher-side companion to cartorio + lacre. Runs the provas pack against an artifact, signs (Ed25519), submits to cartorio, pushes through lacre.";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
  };

  outputs = { self, nixpkgs, crate2nix, flake-utils, fenix, substrate, ... }:
    (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils fenix;
    }) {
      toolName = "tabeliao";
      src = self;
      repo = "pleme-io/tabeliao";
    };
}
