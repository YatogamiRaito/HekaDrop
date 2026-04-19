cask "hekadrop" do
  version "0.5.2"
  sha256 "a3e9612143a6811c05609369984c9eb0b49f27ef39632864b7444575392a083f"

  url "https://github.com/YatogamiRaito/HekaDrop/releases/download/v#{version}/HekaDrop-#{version}.dmg"
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
