{
  description = "Grimoire — password manager CLI and SSH agent for Bitwarden/Vaultwarden";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;

        # Filter source to only include Rust-relevant files
        src = craneLib.cleanCargoSource ./.;

        # Common build inputs shared between deps and main build
        commonArgs = {
          inherit src;
          strictDeps = true;

          buildInputs = [
            pkgs.openssl
            pkgs.sqlite
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          nativeBuildInputs = [
            pkgs.pkg-config
          ];
        };

        # Build dependencies separately for caching
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "grimoire";
        });

        # Main workspace build — produces grimoire, grimoire-service, grimoire-prompt
        grimoire = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "grimoire";
          version = "0.1.0";
          doCheck = true;
        });

        # Native GTK4 prompt (Linux only, separate Cargo project)
        grimoire-prompt-linux = pkgs.rustPlatform.buildRustPackage {
          pname = "grimoire-prompt-linux";
          version = "0.1.0";
          src = ./native/linux;
          cargoLock.lockFile = ./native/linux/Cargo.lock;

          nativeBuildInputs = [ pkgs.pkg-config pkgs.wrapGAppsHook4 ];
          buildInputs = [ pkgs.gtk4 pkgs.libadwaita ];
        };

      in {
        packages = {
          default = grimoire;
          inherit grimoire;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          inherit grimoire-prompt-linux;
        };

        checks = {
          inherit grimoire;
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = [
            pkgs.rust-analyzer
            pkgs.cargo-watch
          ];
        };
      }
    ) // {
      # System-independent outputs

      overlays.default = final: prev: {
        grimoire = self.packages.${final.system}.default;
      };

      nixosModules.default = { pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        services.grimoire.package = pkgs.lib.mkDefault self.packages.${pkgs.system}.default;
      };
    };
}
