#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()      { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()     { echo -e "${RED}[✗]${NC} $1"; }
log_section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

usage() {
    cat <<EOF
Usage: $0 <input.ipa> [OPTIONS]

Required:
  input.ipa            Path to the (decrypted) IPA to resign

Options:
  --cert <hash|name>   Signing identity to use (skips the interactive picker)
  --profile <file>     Provisioning profile to use (skips the interactive picker)
  --install            Install to the connected device via ios-deploy
  --help               Show this help
EOF
    exit 1
}

IPA_PATH=""
CERT=""
PROFILE_PATH=""
INSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install)     INSTALL=1; shift ;;
        --cert)        CERT="${2:-}"; shift 2 ;;
        --profile)     PROFILE_PATH="${2:-}"; shift 2 ;;
        --help|-h)     usage ;;
        -*)            log_err "Unknown option: $1"; usage ;;
        *)
            if [[ -z "$IPA_PATH" ]]; then
                IPA_PATH="$1"
            else
                log_err "Unexpected argument: $1"; usage
            fi
            shift ;;
    esac
done

[[ -z "$IPA_PATH" ]] && usage
[[ ! -f "$IPA_PATH" ]] && { log_err "IPA not found: $IPA_PATH"; exit 1; }

# Extract the string/date value on the line following an exact <key>NAME</key>.
plist_val() { # $1 = decoded plist xml, $2 = key name
    printf '%s\n' "$1" | awk -v k="<key>$2</key>" '
        index($0, k) {
            getline
            gsub(/^[[:space:]]*<(string|date)>/, "")
            gsub(/<\/(string|date)>[[:space:]]*$/, "")
            print
            exit
        }'
}

# True if a provisioning profile embeds the cert with the given SHA-1.
# This is the criterion codesign actually enforces — a profile is usable iff it
# contains the cert whose private key you hold. Team-ID strings are unreliable:
# on a free Personal Team the profile's TeamIdentifier is an App-ID seed that
# differs from the Team ID printed in the cert name.
profile_embeds_cert() { # $1 = provisioning profile path, $2 = cert SHA-1 (hex, no colons)
    local prof="$1" want="$2" tmpf b64 fp i=0
    tmpf=$(mktemp)
    security cms -D -i "$prof" > "$tmpf" 2>/dev/null || { rm -f "$tmpf"; return 1; }
    while b64=$(plutil -extract "DeveloperCertificates.$i" raw -o - "$tmpf" 2>/dev/null); do
        fp=$(printf '%s' "$b64" | base64 -D 2>/dev/null \
             | openssl x509 -inform DER -noout -fingerprint -sha1 2>/dev/null \
             | sed 's/.*=//; s/://g' || true)
        if [[ "$fp" == "$want" ]]; then rm -f "$tmpf"; return 0; fi
        i=$((i + 1))
    done
    rm -f "$tmpf"
    return 1
}

log_section "Selecting signing identity"

CERT_HASHES=()
CERT_NAMES=()
id_re='^[[:space:]]*[0-9]+\)[[:space:]]+([0-9A-F]{40})[[:space:]]+"(.+)"$'
while IFS= read -r line; do
    if [[ "$line" =~ $id_re ]]; then
        CERT_HASHES+=("${BASH_REMATCH[1]}")
        CERT_NAMES+=("${BASH_REMATCH[2]}")
    fi
done < <(security find-identity -v -p codesigning)

if [[ ${#CERT_HASHES[@]} -eq 0 ]]; then
    log_err "No code-signing identities found in your keychain."
    log_warn "Create one: Xcode → Settings → Accounts → add your Apple ID, then build"
    log_warn "any project to your device once. See the repo guide for the full walkthrough."
    exit 1
fi

CHOSEN_CERT_NAME=""
if [[ -n "$CERT" ]]; then
    # --cert given: resolve it to exactly one identity (match hash or name substring).
    match_idx=-1
    for i in "${!CERT_HASHES[@]}"; do
        if [[ "${CERT_HASHES[$i]}" == "$CERT" || "${CERT_NAMES[$i]}" == *"$CERT"* ]]; then
            match_idx=$i; break
        fi
    done
    [[ $match_idx -eq -1 ]] && { log_err "No keychain identity matches: $CERT"; exit 1; }
    CERT="${CERT_HASHES[$match_idx]}"
    CHOSEN_CERT_NAME="${CERT_NAMES[$match_idx]}"
    log_ok "Using identity: $CHOSEN_CERT_NAME"
elif [[ ${#CERT_HASHES[@]} -eq 1 ]]; then
    CERT="${CERT_HASHES[0]}"
    CHOSEN_CERT_NAME="${CERT_NAMES[0]}"
    log_ok "Using the only identity: $CHOSEN_CERT_NAME"
else
    echo "Multiple signing identities found:"
    for i in "${!CERT_HASHES[@]}"; do
        printf "  [%d] %s\n" "$((i + 1))" "${CERT_NAMES[$i]}"
    done
    while :; do
        read -r -p "Select identity [1-${#CERT_HASHES[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#CERT_HASHES[@]} )); then
            break
        fi
        log_warn "Invalid choice."
    done
    CERT="${CERT_HASHES[$((choice - 1))]}"
    CHOSEN_CERT_NAME="${CERT_NAMES[$((choice - 1))]}"
    log_ok "Selected: $CHOSEN_CERT_NAME"
fi

log_section "Selecting provisioning profile"

if [[ -n "$PROFILE_PATH" ]]; then
    [[ ! -f "$PROFILE_PATH" ]] && { log_err "Profile not found: $PROFILE_PATH"; exit 1; }
    log_ok "Using profile: $PROFILE_PATH"
else
    PROFILE_DIRS=(
        "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
        "$HOME/Library/MobileDevice/Provisioning Profiles"
    )
    NOW_EPOCH=$(date "+%s")
    EXPIRED_COUNT=0

    # First pass: gather every valid, non-expired profile, and record whether it
    # embeds the chosen cert (the only thing that makes it usable for signing).
    ALL_PATHS=(); ALL_LABELS=(); ALL_SIGNS=()
    for dir in "${PROFILE_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r prof; do
            [[ -f "$prof" ]] || continue
            decoded=$(security cms -D -i "$prof" 2>/dev/null) || continue

            p_name=$(plist_val "$decoded" "Name")
            p_appid=$(plist_val "$decoded" "application-identifier")
            p_exp=$(plist_val "$decoded" "ExpirationDate")
            exp_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$p_exp" "+%s" 2>/dev/null || echo 0)

            if [[ "$exp_epoch" != 0 && "$exp_epoch" -lt "$NOW_EPOCH" ]]; then
                EXPIRED_COUNT=$((EXPIRED_COUNT + 1))
                continue
            fi

            exp_human="$p_exp"
            [[ "$exp_epoch" != 0 ]] && exp_human=$(date -r "$exp_epoch" "+%Y-%m-%d" 2>/dev/null || echo "$p_exp")

            if profile_embeds_cert "$prof" "$CERT"; then
                signs="yes"; mark="  ✓ signs with your cert"
            else
                signs="no"; mark=""
            fi

            ALL_PATHS+=("$prof")
            ALL_LABELS+=("$(printf '%-42s app=%-26s exp=%s%s' "$p_name" "$p_appid" "$exp_human" "$mark")")
            ALL_SIGNS+=("$signs")
        done < <(find "$dir" -maxdepth 1 -name '*.mobileprovision')
    done

    # Second pass: keep only profiles that embed the chosen cert; else show all
    # (so the user can still force one) with a clear warning that signing may fail.
    PROF_PATHS=(); PROF_LABELS=()
    for i in "${!ALL_PATHS[@]}"; do
        if [[ "${ALL_SIGNS[$i]}" == "yes" ]]; then
            PROF_PATHS+=("${ALL_PATHS[$i]}")
            PROF_LABELS+=("${ALL_LABELS[$i]}")
        fi
    done
    if [[ ${#PROF_PATHS[@]} -eq 0 && ${#ALL_PATHS[@]} -gt 0 ]]; then
        log_warn "No profile embeds your selected cert ($CHOSEN_CERT_NAME)."
        log_warn "Showing all valid profiles, but codesign will likely reject them."
        PROF_PATHS=("${ALL_PATHS[@]}")
        PROF_LABELS=("${ALL_LABELS[@]}")
    fi

    if [[ ${#PROF_PATHS[@]} -eq 0 ]]; then
        log_err "No valid provisioning profiles found."
        [[ "$EXPIRED_COUNT" -gt 0 ]] && log_warn "$EXPIRED_COUNT expired profile(s) were skipped."
        log_warn "Build any project to your device in Xcode once to generate a fresh profile."
        exit 1
    elif [[ ${#PROF_PATHS[@]} -eq 1 ]]; then
        PROFILE_PATH="${PROF_PATHS[0]}"
        log_ok "Using the only matching profile:"
        log_info "  ${PROF_LABELS[0]}"
    else
        echo "Multiple provisioning profiles found:"
        for i in "${!PROF_PATHS[@]}"; do
            printf "  [%d] %s\n" "$((i + 1))" "${PROF_LABELS[$i]}"
        done
        while :; do
            read -r -p "Select profile [1-${#PROF_PATHS[@]}]: " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#PROF_PATHS[@]} )); then
                break
            fi
            log_warn "Invalid choice."
        done
        PROFILE_PATH="${PROF_PATHS[$((choice - 1))]}"
        log_ok "Selected: ${PROF_LABELS[$((choice - 1))]}"
    fi
fi

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT # delete workdir on exit

IPA_BASENAME=$(basename "$IPA_PATH" .ipa) # get file name, strip ".ipa"
OUTPUT_IPA="$(pwd)/${IPA_BASENAME}_resigned.ipa"

log_section "1. Extracting IPA"
unzip -q "$IPA_PATH" -d "$WORK_DIR"
log_ok "Done extracting IPA"

APP_PATH=$(find "$WORK_DIR/Payload" -maxdepth 1 -name "*.app" | head -1)
if [[ -z "$APP_PATH" ]]; then
    log_err "No .app bundle found in Payload/"
    exit 1
fi
log_ok "Found app bundle: $(basename "$APP_PATH")"

log_section "2. Processing Provisioning Profile"

DECODED_PROFILE="$WORK_DIR/decoded_profile.plist"
ENTITLEMENTS="$WORK_DIR/entitlements.plist"

security cms -D -i "$PROFILE_PATH" > "$DECODED_PROFILE"

# Extract entitlements
/usr/libexec/PlistBuddy -x -c 'Print:Entitlements' "$DECODED_PROFILE" > "$ENTITLEMENTS"
log_ok "Entitlements extracted"

# Show profile info
PROFILE_NAME=$(/usr/libexec/PlistBuddy -c 'Print:Name' "$DECODED_PROFILE" 2>/dev/null || echo "Unknown")
TEAM_ID=$(/usr/libexec/PlistBuddy -c 'Print:TeamIdentifier:0' "$DECODED_PROFILE" 2>/dev/null || echo "Unknown")
APP_ID=$(/usr/libexec/PlistBuddy -c 'Print:Entitlements:application-identifier' "$DECODED_PROFILE" 2>/dev/null || echo "Unknown")
EXPIRY=$(/usr/libexec/PlistBuddy -c 'Print:ExpirationDate' "$DECODED_PROFILE" 2>/dev/null || echo "Unknown")

log_info "Profile Name : $PROFILE_NAME"
log_info "Team ID      : $TEAM_ID"
log_info "App ID       : $APP_ID"
log_info "Expiry       : $EXPIRY"

# Check expiry
EXPIRY_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$(/usr/libexec/PlistBuddy -c 'Print:ExpirationDate' "$DECODED_PROFILE" 2>/dev/null | sed 's/ +0000//')" "+%s" 2>/dev/null || echo "0")
NOW_EPOCH=$(date "+%s")
if [[ "$EXPIRY_EPOCH" != "0" && "$EXPIRY_EPOCH" -lt "$NOW_EPOCH" ]]; then
    log_err "Provisioning profile has expired - can not continue."
    exit 1
fi

log_section "3. Updating Bundle ID"

CURRENT_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print:CFBundleIdentifier" "$APP_PATH/Info.plist")
log_info "Original Bundle ID: $CURRENT_BUNDLE_ID"

# Get bundle ID from profile (strip team prefix: TEAMID.com.bundle.id → com.bundle.id)
PROFILE_BUNDLE_ID=$(echo "$APP_ID" | sed 's/^[A-Z0-9]*\.//')
log_info "Profile Bundle ID : $PROFILE_BUNDLE_ID"

# Only update if not wildcard and different
if [[ "$PROFILE_BUNDLE_ID" != "*" && "$CURRENT_BUNDLE_ID" != "$PROFILE_BUNDLE_ID" ]]; then
    /usr/libexec/PlistBuddy -c "Set:CFBundleIdentifier $PROFILE_BUNDLE_ID" "$APP_PATH/Info.plist"
    log_ok "Bundle ID updated → $PROFILE_BUNDLE_ID"
else
    log_ok "Bundle ID kept: $CURRENT_BUNDLE_ID"
fi

log_section "4. Injecting Provisioning Profile"
cp "$PROFILE_PATH" "$APP_PATH/embedded.mobileprovision"
log_ok "Provisioning profile injected"

log_section "5. Code Signing"

sign_item() {
    local item="$1"
    local extra_args="${2:-}"
    if codesign --force --sign "$CERT" --timestamp=none $extra_args "$item"; then
        log_ok "Signed: $(basename "$item")"
    else
        log_warn "Skip (not signable): $(basename "$item")"
    fi
}

# Sign dylibs
log_info "Signing .dylib files..."
find "$APP_PATH" -name "*.dylib" | sort | while read -r f; do
    sign_item "$f"
done

# Sign .so files
log_info "Signing .so files..."
find "$APP_PATH" -name "*.so" | sort | while read -r f; do
    sign_item "$f"
done

# Sign frameworks (inner first by depth)
log_info "Signing .framework bundles..."
find "$APP_PATH" -name "*.framework" | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2- | while read -r f; do
    sign_item "$f"
done

# Sign app extensions
log_info "Signing .appex extensions..."
find "$APP_PATH" -name "*.appex" | while read -r f; do
    sign_item "$f" "--entitlements $ENTITLEMENTS"
done

# Sign bundles that contain executables
log_info "Signing .bundle files..."
find "$APP_PATH" -name "*.bundle" | while read -r f; do
    sign_item "$f"
done

# Sign standalone executables (Mach-O binaries without extension)
log_info "Signing standalone executables..."
find "$APP_PATH" -type f -perm +111 ! -name "*.*" ! -path "*/Frameworks/*" | while read -r f; do
    if file "$f" | grep -q "Mach-O"; then
        sign_item "$f"
    fi
done

# Finally sign the app bundle itself
log_info "Signing app bundle (final)..."
codesign --force \
         --sign "$CERT" \
         --entitlements "$ENTITLEMENTS" \
         --timestamp=none \
         "$APP_PATH"
log_ok "App bundle signed"

log_section "6. Verifying Signature"

if codesign --verify --deep --strict --verbose=2 "$APP_PATH" 2>&1; then
    log_ok "Signature is VALID"
else
    log_err "Signature verification FAILED"
    exit 1
fi

# Show signing info
echo ""
log_info "Signing details:"
codesign -dv "$APP_PATH" 2>&1 | grep -E "Authority|TeamIdentifier|Identifier|Signed Time"

log_section "Step 7: Package / Install"

if [[ "${INSTALL:-0}" == "1" ]]; then
    if ! command -v ios-deploy &>/dev/null; then
        log_err "ios-deploy not found. Install: brew install ios-deploy"
        exit 1
    fi

    log_info "Installing directly to device..."
    if ios-deploy --bundle "$APP_PATH" -W; then
        log_ok "Installed successfully"
    else
        log_err "Install failed"
        exit 1
    fi
else
    log_info "Repacking IPA..."
    (cd "$WORK_DIR" && zip -qr "$OUTPUT_IPA" Payload/)
    log_ok "IPA created: $OUTPUT_IPA"
fi

log_section "Done"
