{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            (texliveFull.withPackages (
              p: with p; [
                titlesec
                enumitem
              ]
            ))
            texlab # For LSP
          ];
          # shellHook = ''
          #   code &&
          #   latexmk -pdf main.tex -interaction=nonstopmode -pvc -view=none
          # '';
        };
      }
    );
}
