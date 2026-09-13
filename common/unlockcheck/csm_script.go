// Package unlockcheck provides streaming unlock detection functionality.
// 协议信号参考：
// https://github.com/1-stream/RegionRestrictionCheck/blob/main/check.sh
// https://github.com/xykt/RegionRestrictionCheck/blob/main/check.sh
// 接口异常、反爬页面或缺少判定字段时返回 Unknown。
package unlockcheck

// CSM_SCRIPT 在本地执行；各检查独立请求服务，不下载远程脚本。
const CSM_SCRIPT = `#!/bin/bash
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

# 每个后台检查有独立的变量；curl 失败时不使用部分响应。
request() {
    local response
    BODY="" CODE="" FINAL_URL=""
    response=$(curl -q -sS -L --compressed --connect-timeout 5 --max-time 15 --max-redirs 5 --user-agent "$UA_BROWSER" -H 'accept-language: en-US,en;q=0.9' "$@" -w '\n%{http_code}\n%{url_effective}') || return 1
    FINAL_URL=${response##*$'\n'}
    response=${response%$'\n'*}
    CODE=${response##*$'\n'}
    BODY=${response%$'\n'*}
    [[ "$CODE" =~ ^[1-5][0-9]{2}$ ]]
}

# 仅接受完整、唯一的地区字段，不截断长字符串或猜测 IP 地区。
regionFrom() {
    grep -oP "$1" <<< "$2" | sort -u | awk 'NR == 1 {value=$0} END {if (NR == 1) print toupper(value)}'
}

writeResult() {
    printf '%s\n' "$2" > "$RESULT_DIR/$1"
}

mergeResults() {
    local service result sep=""
    printf '{'
    for service in YouTube_Premium Netflix DisneyPlus HBOMax AmazonPrime OpenAI Gemini Claude TikTok; do
        result=$(cat "$RESULT_DIR/$service" 2>/dev/null)
        # 输出值只由检测器构造；拒绝异常文件内容污染 JSON。
        if [[ ! "$result" =~ ^(Yes(\ \([A-Z]{2,3}\))?|No(\ \(Originals\ Only\))?|Unknown|仅限网页|仅限App)$ ]]; then
            result="Unknown"
        fi
        printf '%s"%s":"%s"' "$sep" "$service" "$result"
        sep=,
    done
    printf '}\n'
}

nf_region_from_html() {
    regionFrom '"requestCountry"\s*:\s*\{[^}]*"id"\s*:\s*"\K[A-Z]{2}(?=")' "$1"
}

UnlockTest_Netflix() {
    local title body code region="" available=0 unavailable=0
    for title in 81280792 70143836; do
        if ! request "https://www.netflix.com/title/$title"; then
            continue
        fi
        body=$BODY code=$CODE
        if [[ "$body" == *NSEZ-403* ]]; then
            writeResult Netflix No
            return
        fi
        if [[ "$code" == 200 ]] && grep -qE "property=[\"']og:video(:url|:secure_url)?[\"']" <<< "$body"; then
            available=1
            [[ -n "$region" ]] || region=$(nf_region_from_html "$body")
        elif [[ "$code" == 404 ]] || { [[ "$code" == 200 ]] && grep -qE 'Oh no!|page-404' <<< "$body"; }; then
            ((unavailable+=1))
        fi
    done
    if [[ "$available" == 1 ]]; then
        writeResult Netflix "Yes${region:+ ($region)}"
    elif [[ "$unavailable" == 2 ]]; then
        # 确认自制内容仍可访问，不能把两个错误页直接当成“仅自制”。
        if request 'https://www.netflix.com/title/80018499' && [[ "$CODE" == 200 ]] && grep -q 'og:video' <<< "$BODY"; then
            writeResult Netflix 'No (Originals Only)'
        else
            writeResult Netflix Unknown
        fi
    else
        writeResult Netflix Unknown
    fi
}

UnlockTest_YouTube_Premium() {
    local region
    if ! request 'https://www.youtube.com/premium' -H 'cookie: SOCS=CAISNQgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgJlbiACGgYIgNzEsgY' || [[ "$CODE" != 200 ]]; then
        writeResult YouTube_Premium Unknown
    elif grep -qi 'Premium is not available in your country' <<< "$BODY"; then
        writeResult YouTube_Premium No
    elif grep -qE 'purchaseButtonOverride|Start trial' <<< "$BODY"; then
        region=$(regionFrom '"INNERTUBE_CONTEXT_GL"\s*:\s*"\K[A-Z]{2}(?=")' "$BODY")
        writeResult YouTube_Premium "Yes${region:+ ($region)}"
    else
        writeResult YouTube_Premium Unknown
    fi
}

UnlockTest_DisneyPlus() {
    local auth='ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84'
    local assertion refreshToken region supported
    writeResult DisneyPlus Unknown
    request 'https://disney.api.edge.bamgrid.com/devices' -H "authorization: Bearer $auth" -H 'content-type: application/json' --data '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' || return
    if grep -q 'forbidden-location' <<< "$BODY"; then writeResult DisneyPlus No; return; fi
    [[ "$CODE" == 200 || "$CODE" == 201 ]] || return
    assertion=$(grep -oP '"assertion"\s*:\s*"\K[A-Za-z0-9._-]+(?=")' <<< "$BODY")
    [[ -n "$assertion" ]] || return
    request 'https://disney.api.edge.bamgrid.com/token' -H "authorization: Bearer $auth" --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' --data-urlencode "subject_token=$assertion" --data-urlencode 'subject_token_type=urn:bamtech:params:oauth:token-type:device' --data 'latitude=0&longitude=0&platform=browser' || return
    if grep -q 'forbidden-location' <<< "$BODY"; then writeResult DisneyPlus No; return; fi
    [[ "$CODE" == 200 ]] || return
    refreshToken=$(grep -oP '"refresh_token"\s*:\s*"\K[A-Za-z0-9._-]+(?=")' <<< "$BODY")
    [[ -n "$refreshToken" ]] || return
    local payload='{"query":"mutation refreshToken($input: RefreshTokenInput!) {refreshToken(refreshToken: $input) {activeSession {sessionId}}}","variables":{"input":{"refreshToken":"'"$refreshToken"'"}}}'
    request 'https://disney.api.edge.bamgrid.com/graph/v1/device/graphql' -H "authorization: $auth" -H 'content-type: application/json' --data "$payload" || return
    [[ "$CODE" == 200 ]] || return
    region=$(regionFrom '"countryCode"\s*:\s*"\K[A-Z]{2}(?=")' "$BODY")
    supported=$(grep -oP '"inSupportedLocation"\s*:\s*\K(true|false)(?=[,}\s])' <<< "$BODY" | sort -u)
    [[ -n "$region" && -n "$supported" ]] || return
    if [[ "$supported" == true || ( "$region" == JP && "$supported" == false ) ]]; then
        writeResult DisneyPlus "Yes ($region)"
    elif [[ "$supported" == false ]]; then
        writeResult DisneyPlus No
    fi
}

UnlockTest_HBOMax() {
    local token tenant market env domain region available countries
    local headers=(-H 'x-disco-client: WEB:10.15.7:dotcom-hbomax:7.7.0' -H 'x-disco-params: realm=bolt,bid=beam,features=ar' -H 'x-device-info: beam/5.0.0 (desktop/desktop; Windows/10; afbb5daa-c327-461d-9460-d8e4b3ee4a1f/da0cdd94-5a39-42ef-aa68-54cbc1b852c3)')
    writeResult HBOMax Unknown
    request 'https://default.any-any.prd.api.hbomax.com/token?realm=bolt&deviceId=afbb5daa-c327-461d-9460-d8e4b3ee4a1f' "${headers[@]}" || return
    [[ "$CODE" == 200 ]] || return
    token=$(grep -oP '"token"\s*:\s*"\K[A-Za-z0-9._-]+(?=")' <<< "$BODY")
    [[ -n "$token" ]] || return
    request 'https://default.any-any.prd.api.hbomax.com/session-context/headwaiter/v1/bootstrap' "${headers[@]}" -X POST -b "st=$token" || return
    [[ "$CODE" == 200 ]] || return
    tenant=$(grep -oP '"tenant"\s*:\s*"\K[a-z]+(?=")' <<< "$BODY")
    market=$(grep -oP '"homeMarket"\s*:\s*"\K[a-z]+(?=")' <<< "$BODY")
    env=$(grep -oP '"env"\s*:\s*"\K[a-z]+(?=")' <<< "$BODY")
    domain=$(grep -oP '"domain"\s*:\s*"\K[^" ]+' <<< "$BODY")
    [[ -n "$tenant" && -n "$market" && "$env" == prd && "$domain" == api.hbomax.com ]] || return
    request "https://default.$tenant-$market.$env.$domain/users/me" "${headers[@]}" -b "st=$token" || return
    [[ "$CODE" == 200 ]] || return
    region=$(regionFrom '"currentLocationTerritory"\s*:\s*"\K[A-Za-z]{2}(?=")' "$BODY")
    [[ -n "$region" ]] || return
    request 'https://www.hbomax.com/' || return
    [[ "$CODE" == 200 ]] || return
    # 首页 userCountry / isUserOutOfRegion 不证明可用；使用会话地区和当前服务地区列表。
    countries=$(grep -oP '"countryLangUris"\s*:\s*\{(?:[^{}]|\{[^{}]*\})*\}' <<< "$BODY")
    available=$(grep -oP '"url"\s*:\s*"/\K[a-z]{2}(?=/[a-z]{2}")' <<< "$countries" | sort -u | tr 'a-z' 'A-Z')
    [[ -n "$available" ]] || return
    if grep -qx "$region" <<< "$available"; then
        writeResult HBOMax "Yes ($region)"
    else
        writeResult HBOMax No
    fi
}

UnlockTest_PrimeVideo() {
    local region
    writeResult AmazonPrime Unknown
    request 'https://www.primevideo.com/' || return
    [[ "$CODE" == 200 ]] || return
    if grep -qE '"isServiceRestricted"\s*:\s*true' <<< "$BODY"; then
        writeResult AmazonPrime No
        return
    fi
    region=$(regionFrom '"currentTerritory"\s*:\s*"\K[A-Z]{2}(?=")' "$BODY")
    [[ -n "$region" ]] || return
    request 'https://ab9f7h23rcdn.eu.api.amazonvideo.com/cdp/appleedge/getDataByTransform/v1/apple/detail/vod/v1.kt?itemId=amzn1.dv.gti.e6b39984-2bb6-f7d0-33e4-08ec574947f0&deviceId=6F97F9CCFA2243F1A3C44BD3C7F7908E&deviceTypeId=A3JTVZS31ZJ340&density=2x&firmware=10.6800.16104.3&format=json&enabledFeatures=denarius.location.gen4.daric.siglos.siglosPartnerBilling.contentDescriptors.contentDescriptorsV2.productPlacement.zeno.seriesSearch.tapsV2.dateTimeLocalization.multiSourcedEvents.mseEventLevelOffers.liveWatchModal.lbv.daapi.maturityRatingDecoration.seasonTrailer.cleanSlate.xbdModalV2.xbdModalVdp.playbackPinV2.exploreTab.reactions.progBadging.atfEpTimeVis.prereleaseCx.vppaConsent.episodicRelease.movieVam.movieVamCatalog&journeyIngressContext=8%7CEgRzdm9k&osLocale=zh_Hans_CN&timeZoneId=Asia%2FShanghai&uxLocale=zh_CN' || return
    [[ "$CODE" == 200 ]] || return
    if grep -qiE '您的设备使用了 VPN 或代理服务|your device is connected to the internet using a VPN or proxy' <<< "$BODY"; then
        writeResult AmazonPrime No
    elif grep -qE '"isPlayableOnThisDevice"\s*:\s*true' <<< "$BODY" && grep -qE '"hasPlayableOffer"\s*:\s*true' <<< "$BODY"; then
        writeResult AmazonPrime "Yes ($region)"
    fi
}

UnlockTest_OpenAI() {
    local web=Unknown app=Unknown region
    # 网页直接探测 ChatGPT，API cookie 接口不能证明网页可用。
    if request 'https://chatgpt.com/'; then
        if grep -qiE 'unsupported_country|not available in your country' <<< "$BODY"; then
            web=No
        elif [[ "$CODE" == 200 && "$FINAL_URL" == https://chatgpt.com/* ]] && grep -qiE '__next|__reactRouter|<title>ChatGPT</title>' <<< "$BODY"; then
            web=Yes
        fi
    fi
    if request 'https://ios.chat.openai.com/' -H 'accept: application/json'; then
        if grep -qiE 'unsupported_country|VPN|disallowed isp|blocked_why_headline|"cf_details"\s*:\s*"Request is not allowed' <<< "$BODY"; then
            app=No
        elif [[ "$CODE" == 200 ]] && grep -qE '^\s*\{\s*\}\s*$' <<< "$BODY"; then
            app=Yes
        fi
    fi
    if [[ "$web" == Yes && "$app" == Yes ]]; then
        if request 'https://chatgpt.com/cdn-cgi/trace' && [[ "$CODE" == 200 ]]; then
            region=$(regionFrom '^loc=\K[A-Z]{2}(?=\r?$)' "$BODY")
        fi
        writeResult OpenAI "Yes${region:+ ($region)}"
    elif [[ "$web" == Yes && "$app" == No ]]; then
        writeResult OpenAI 仅限网页
    elif [[ "$web" == No && "$app" == Yes ]]; then
        writeResult OpenAI 仅限App
    elif [[ "$web" == No && "$app" == No ]]; then
        writeResult OpenAI No
    else
        writeResult OpenAI Unknown
    fi
}

UnlockTest_Gemini() {
    local region
    writeResult Gemini Unknown
    request 'https://gemini.google.com/' || return
    [[ "$CODE" == 200 && "$FINAL_URL" == https://gemini.google.com/* ]] || return
    if grep -qE '45631641,\s*null,\s*true' <<< "$BODY"; then
        region=$(regionFrom ',2,1,200,"\K[A-Z]{3}(?=")' "$BODY")
        writeResult Gemini "Yes${region:+ ($region)}"
    elif grep -qE '45631641,\s*null,\s*false' <<< "$BODY"; then
        writeResult Gemini No
    fi
}

UnlockTest_Claude() {
    local region
    writeResult Claude Unknown
    request 'https://claude.ai/' || return
    [[ "$CODE" == 200 ]] || return
    case "$FINAL_URL" in
        https://claude.ai/*app-unavailable-in-region*|https://claude.com/*app-unavailable-in-region*|https://www.claude.com/*app-unavailable-in-region*)
            writeResult Claude No ;;
        https://claude.ai/*)
            # 原网址上的反爬/错误页不是成功信号。
            if grep -qiE '__NEXT_DATA__|/_next/static/|<title>Claude</title>' <<< "$BODY" && ! grep -qiE 'cf-chl-|Just a moment|challenge-platform' <<< "$BODY"; then
                if request 'https://claude.ai/cdn-cgi/trace' && [[ "$CODE" == 200 ]]; then
                    region=$(regionFrom '^loc=\K[A-Z]{2}(?=\r?$)' "$BODY")
                fi
                writeResult Claude "Yes${region:+ ($region)}"
            fi ;;
    esac
}

UnlockTest_TikTok() {
    local region
    writeResult TikTok Unknown
    request 'https://www.tiktok.com/' || return
    [[ "$CODE" == 200 ]] || return
    if [[ "$FINAL_URL" == https://www.tiktok.com/hk/notfound* || "$FINAL_URL" == https://www.tiktok.com/*/notfound* ]] || grep -qiE 'not available in your region|TikTok is not available' <<< "$BODY"; then
        writeResult TikTok No
        return
    fi
    [[ "$FINAL_URL" == https://www.tiktok.com/* ]] || return
    if grep -qiE '<title>Please wait|<title>[^<]*[Cc]aptcha|[Vv]erify to continue' <<< "$BODY"; then return; fi
    # store_region 是服务端对当前访问者的结果，首页任意 region 可能属于视频作者。
    request 'https://www.tiktok.com/passport/web/store_region/' -X POST || return
    [[ "$CODE" == 200 ]] || return
    region=$(regionFrom '"store_region"\s*:\s*"\K[A-Za-z]{2}(?=")' "$BODY")
    grep -qE '"message"\s*:\s*"success"' <<< "$BODY" || return
    if [[ "$region" == CN ]]; then
        writeResult TikTok No
    elif [[ -n "$region" ]]; then
        writeResult TikTok "Yes ($region)"
    fi
}

runCheck() {
    RESULT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ecycloudnode-unlock.XXXXXXXX") || return 1
    trap 'rm -rf -- "$RESULT_DIR"' EXIT
    UnlockTest_YouTube_Premium &
    UnlockTest_Netflix &
    UnlockTest_DisneyPlus &
    UnlockTest_HBOMax &
    UnlockTest_PrimeVideo &
    UnlockTest_OpenAI &
    UnlockTest_Gemini &
    UnlockTest_Claude &
    UnlockTest_TikTok &
    wait
    mergeResults
}

runCheck
`
