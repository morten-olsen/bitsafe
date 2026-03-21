{ config, lib, pkgs, ... }:

let
  cfg = config.services.grimoire;

  configFile = pkgs.writeText "grimoire-config.toml" ''
    [server]
    url = "${cfg.settings.server_url}"

    [prompt]
    method = "${cfg.settings.prompt_method}"

    [ssh_agent]
    enabled = ${lib.boolToString cfg.ssh-agent.enable}
  '';
in
{
  options.services.grimoire = {
    enable = lib.mkEnableOption "Grimoire password manager service";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The Grimoire package to use.";
    };

    settings = {
      server_url = lib.mkOption {
        type = lib.types.str;
        default = "https://vault.bitwarden.com";
        description = "Bitwarden/Vaultwarden server URL.";
      };

      prompt_method = lib.mkOption {
        type = lib.types.enum [ "auto" "gui" "terminal" "none" ];
        default = "auto";
        description = "How the service obtains credentials interactively.";
      };
    };

    ssh-agent = {
      enable = lib.mkEnableOption "Grimoire SSH agent";
    };
  };

  config = lib.mkIf cfg.enable {
    # Ensure the package is available in PATH
    environment.systemPackages = [ cfg.package ];

    # Systemd user service
    systemd.user.services.grimoire = {
      description = "Grimoire password manager service";
      wantedBy = [ "default.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/grimoire-service";
        Restart = "on-failure";
        RestartSec = 5;

        # Memory protection — prevent swap and core dumps
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        RestrictRealtime = true;
      };

      environment = {
        GRIMOIRE_CONFIG = "${configFile}";
      } // lib.optionalAttrs cfg.ssh-agent.enable {
        SSH_AUTH_SOCK = "%t/grimoire/ssh-agent.sock";
      };
    };

    # Set SSH_AUTH_SOCK globally when SSH agent is enabled
    environment.sessionVariables = lib.mkIf cfg.ssh-agent.enable {
      SSH_AUTH_SOCK = "\${XDG_RUNTIME_DIR}/grimoire/ssh-agent.sock";
    };
  };
}
