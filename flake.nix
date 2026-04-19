{
  description = "Dev environment for simpleauth";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";

    # 1.19.1 release
    go_dep.url = "github:NixOS/nixpkgs/8ba120420fbdd9bd35b3a5366fa0206d8c99ade3";

    # 0.9.0 release
    shellcheck_dep.url = "github:NixOS/nixpkgs/8b5ab8341e33322e5b66fb46ce23d724050f6606";
  };

  outputs = {
    self,
    flake-utils,
    go_dep,
    shellcheck_dep,
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (system: let
      gopkg = inputs.go_dep.legacyPackages.${system};
      shellcheckPkg = inputs.shellcheck_dep.legacyPackages.${system};
      go = gopkg.go_1_19;
      buildGoModule = gopkg.buildGoModule.override {inherit go;};

      goVendorHash = "sha256-o2xdGtqcUX0n8zpEaw5YMdzkUDQLHvXW3+pB2s7f8AU=";
      staticcheckVendorHash = "sha256-dUO2Iw+RYk8s+3IV2/TSKjaX61YkD/AROq3177r+wKE=";
      errcheckVendorHash = "sha256-96+927gNuUMovR4Ru/8BwsgEByNq2EPX7wXWS7+kSL8=";

      goModules = buildGoModule {
        pname = "simpleauth-go-modules";
        version = "0.0.0";
        src = gopkg.lib.cleanSource ./.;
        vendorHash = goVendorHash;
        doCheck = false;
      };

      staticcheck = buildGoModule {
        pname = "staticcheck";
        version = "0.4.6";
        src = gopkg.fetchFromGitHub {
          owner = "dominikh";
          repo = "go-tools";
          rev = "v0.4.6";
          hash = "sha256-Ecp3A3Go7mp8/ghMjTGqCNlRkCeEAb3fzRuwahWcM2I=";
        };
        vendorHash = staticcheckVendorHash;
        subPackages = ["cmd/staticcheck"];
        doCheck = false;
      };

      errcheck = buildGoModule {
        pname = "errcheck";
        version = "1.6.2";
        src = gopkg.fetchFromGitHub {
          owner = "kisielk";
          repo = "errcheck";
          rev = "v1.6.2";
          hash = "sha256-lx1kbRyL9OJzTxClIej/FisfVRh2VG98HGOBuF359LI=";
        };
        vendorHash = errcheckVendorHash;
        doCheck = false;
      };

      mkBuildStep = {
        name,
        command,
        extraInputs ? [],
        setup ? "",
      }:
        gopkg.stdenvNoCC.mkDerivation {
          pname = name;
          version = "0.0.0";
          src = self;
          nativeBuildInputs = [gopkg.bash] ++ extraInputs;
          buildPhase = ''
            runHook preBuild

            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"

            export GOPATH="$TMPDIR/go"
            export GOCACHE="$TMPDIR/go-cache"
            export GOMODCACHE="$TMPDIR/go-mod"
            mkdir -p "$GOPATH" "$GOCACHE" "$GOMODCACHE"

            export CI=1

            patchShebangs ./dev-scripts
            ${setup}
            ${command}

            runHook postBuild
          '';
          installPhase = ''
            mkdir -p "$out"
            echo "${name}" > "$out/done"
          '';
        };
    in {
      packages = {
        check-bash = mkBuildStep {
          name = "check-bash";
          command = "./dev-scripts/check-bash";
          extraInputs = [gopkg.git shellcheckPkg.shellcheck];
          setup = ''
            git init --quiet
            git add --all
          '';
        };

        check-go-formatting = mkBuildStep {
          name = "check-go-formatting";
          command = "./dev-scripts/check-go-formatting";
          extraInputs = [go];
        };

        check-trailing-newline = mkBuildStep {
          name = "check-trailing-newline";
          command = "./dev-scripts/check-trailing-newline";
          extraInputs = [
            gopkg.coreutils
            gopkg.findutils
            gopkg.git
            gopkg.gnugrep
          ];
          setup = ''
            git init --quiet
            git add --all
          '';
        };

        check-trailing-whitespace = mkBuildStep {
          name = "check-trailing-whitespace";
          command = "./dev-scripts/check-trailing-whitespace";
          extraInputs = [
            gopkg.coreutils
            gopkg.findutils
            gopkg.git
            gopkg.gnugrep
          ];
          setup = ''
            git init --quiet
            git add --all
          '';
        };

        go-tests = mkBuildStep {
          name = "go-tests";
          command = "./dev-scripts/run-go-tests --full";
          extraInputs = [
            errcheck
            go
            gopkg.binutils
            gopkg.gcc
            staticcheck
          ];
          setup = ''
            cp --recursive ${goModules."go-modules"} vendor
            chmod --recursive u+w vendor
            export GOFLAGS="-mod=vendor"

            mkdir -p "$GOPATH/bin"
            ln --symbolic ${staticcheck}/bin/staticcheck "$GOPATH/bin/staticcheck"
            ln --symbolic ${errcheck}/bin/errcheck "$GOPATH/bin/errcheck"
          '';
        };
      };

      devShells.default = gopkg.mkShell.override {stdenv = gopkg.pkgsStatic.stdenv;} {
        packages = [
          gopkg.gotools
          gopkg.gopls
          gopkg.go-outline
          gopkg.gocode
          gopkg.gopkgs
          gopkg.gocode-gomod
          gopkg.godef
          gopkg.golint
          go
          shellcheckPkg.shellcheck
        ];

        shellHook = ''
          GOROOT="$(dirname $(dirname $(which go)))/share/go"
          export GOROOT

          echo "shellcheck" "$(shellcheck --version | grep '^version:')"
          go version
        '';
      };

      formatter = gopkg.alejandra;
    });
}
