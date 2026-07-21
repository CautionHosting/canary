# Canary V0 release shape. Copy this file to caution.hcl only after the public
# source URL and HTTPS domain have been independently chosen and reviewed. The
# deployment validator rejects either placeholder.
enclave "main" {
  build {
    containerfile = "Containerfile"
    app_sources = [
      "https://codeberg.org/vkobel/canary",
    ]
  }

  network {
    ingress {
      cidr_ipv4   = "0.0.0.0/0"
      port        = 8080
      ip_protocol = "tcp"
    }

    # Caution currently treats any egress rule as enabling egress. Keep the
    # intended broad TCP/443 policy explicit until per-rule enforcement lands.
    egress {
      cidr_ipv4   = "0.0.0.0/0"
      port        = 443
      ip_protocol = "tcp"
    }

    http {
      domain = "canary.kobl.one"
      port   = 8080
    }
  }

  # Deliberately omit resources: use Caution's defaults.
  unit "default" {
    command = "/app/canaryd"
    args    = ["--ephemeral-identity"]
  }
}
