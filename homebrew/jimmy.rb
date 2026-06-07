# Homebrew formula for jimmy.
# Users install with: brew tap christiancattaneo/jimmy && brew install jimmy
#
# jimmy is a Node CLI published to npm as `jimmy-db` (the binary is `jimmy`).
# This formula installs that package's published tarball and links the bin.
# Update `version` and `sha256` on each release:
#   curl -sL https://registry.npmjs.org/jimmy-db/-/jimmy-db-<version>.tgz | shasum -a 256

class Jimmy < Formula
  desc "Pries open the database the app thinks is locked: RLS, isolation, anomalies, migrations"
  homepage "https://jimmy-sage.vercel.app"
  url "https://registry.npmjs.org/jimmy-db/-/jimmy-db-0.1.0.tgz"
  sha256 "PLACEHOLDER_SHA256_UPDATE_ON_PUBLISH"
  license "MIT"
  version "0.1.0"

  depends_on "node"

  def install
    system "npm", "install", *Language::Node.std_npm_install_args(libexec)
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    assert_match "0.1.0", shell_output("#{bin}/jimmy --version")
  end
end
