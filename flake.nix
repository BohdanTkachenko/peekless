{
  description = "peekless — hand secrets to an AI agent's command without the agent seeing them";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAll (pkgs: rec {
        peekless = pkgs.rustPlatform.buildRustPackage {
          pname = "peekless";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = "Hand secrets to an AI agent's command without the agent seeing them";
            license = with pkgs.lib.licenses; [ mit asl20 ];
            mainProgram = "peekless";
          };
        };
        default = peekless;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer ];
        };
      });
    };
}
