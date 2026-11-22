# The formula of avbel/homebrew-tap (Formula/vaultkeeper.rb). Committed to the tap by hand once;
# afterwards the release workflow's `homebrew` job rewrites version and the two sha256 lines with
# scripts/bump-homebrew.rb. Linux only: macOS uses the cask (vaultkeeper-cask.rb).
class Vaultkeeper < Formula
  desc "Bitwarden-compatible password manager for the desktop"
  homepage "https://github.com/avbel/vaultkeeper"
  version "0.0.0"
  license "GPL-3.0-only"

  depends_on :linux

  on_linux do
    on_intel do
      url "https://github.com/avbel/vaultkeeper/releases/download/v#{version}/vaultkeeper-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_arm do
      url "https://github.com/avbel/vaultkeeper/releases/download/v#{version}/vaultkeeper-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "bin/vaultkeeper"
    (share/"vaultkeeper").install Dir["share/vaultkeeper/*"]
  end

  def caveats
    <<~EOS
      Vaultkeeper writes its launcher entry on first start; run `vaultkeeper` once.
      It links the desktop's own libraries; install them if they are missing:
        Ubuntu: sudo apt install libxkbcommon0 libwayland-client0 libegl1 libfontconfig1 libudev1
        Fedora: sudo dnf install libxkbcommon libwayland-client mesa-libEGL fontconfig systemd-libs
      "Start at login" is in Vaultkeeper's Settings; there is no `brew services` entry.
      Updates come from `brew upgrade vaultkeeper`.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vaultkeeper --version")
  end
end
