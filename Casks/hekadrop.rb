cask "hekadrop" do
  version "0.5.1"
  sha256 "5507c34078353041834de83a06b1afa219df7ac6158864fdc372cb8cc63c6052"

  url "https://github.com/YatogamiRaito/HekaDrop/releases/download/v#{version}/HekaDrop-#{version}-macos.zip"
  name "HekaDrop"
  desc "Google Quick Share (Nearby Share) client — Rust, cross-platform"
  homepage "https://github.com/YatogamiRaito/HekaDrop"

  auto_updates false
  depends_on macos: ">= :big_sur"

  app "HekaDrop.app"

  uninstall quit:      "com.sourvice.hekadrop",
            launchctl: "com.sourvice.hekadrop"

  zap trash: [
    "~/Library/Application Support/HekaDrop",
    "~/Library/Logs/HekaDrop",
    "~/Library/LaunchAgents/com.sourvice.hekadrop.plist",
    "~/Library/Preferences/com.sourvice.hekadrop.plist",
  ]
end
