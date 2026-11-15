# winget manifests

winget-releaser (the `winget` job in `.github/workflows/release.yml`) only updates a package that
already exists in microsoft/winget-pkgs, so the first version is submitted by hand.

1. Wait for a release whose Windows installer is code-signed (job `windows-package` reported
   `signed=true`), so `Vaultkeeper-v<version>-x64-setup.exe` is on the GitHub release.
2. Submit it, from a fork of microsoft/winget-pkgs owned by the account behind `WINGET_TOKEN`:

   ```
   komac new avbel.Vaultkeeper --version <version> \
     --urls https://github.com/avbel/vaultkeeper/releases/download/v<version>/Vaultkeeper-v<version>-x64-setup.exe \
     --submit
   ```

   or

   ```
   wingetcreate new https://github.com/avbel/vaultkeeper/releases/download/v<version>/Vaultkeeper-v<version>-x64-setup.exe
   ```

   Answer the prompts with the values in the yaml files here (InstallerType inno, Scope user,
   MinimumOSVersion 10.0.26100.0, UpgradeBehavior install, command `vaultkeeper`). The files in this
   directory are the reference manifests; keep PackageVersion and InstallerUrl in step with the
   release you submit and fill in InstallerSha256.
3. Once the PR is merged, every later signed release is submitted by CI.

Secrets: `WINGET_TOKEN` is a classic PAT with `public_repo` scope in the `winget` environment of this
repository, owned by the account that forked microsoft/winget-pkgs.
