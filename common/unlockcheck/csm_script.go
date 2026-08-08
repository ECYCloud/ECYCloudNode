// Package unlockcheck provides streaming unlock detection functionality.
// This file contains the embedded csm.sh script for local execution.
// Script source: https://github.com/ECYCloud/check-stream-media
// All detection logic is embedded locally, no remote download required.
// Optimized for parallel execution to reduce detection time.
package unlockcheck

// CSM_SCRIPT contains the complete csm.sh script for unlock detection.
// This script is executed locally without downloading from remote.
// Uses parallel execution for faster detection (typically 10-15 seconds).
const CSM_SCRIPT = `#!/bin/bash
shopt -s expand_aliases

UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
UA_SEC_CH_UA='"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"'
CURL_DEFAULT_OPTS="-s --max-time 8"

# Disney+ cookies embedded locally
DISNEY_COOKIE_1='grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&latitude=0&longitude=0&platform=browser&subject_token=DISNEYASSERTION&subject_token_type=urn%3Abamtech%3Aparams%3Aoauth%3Atoken-type%3Adevice'
DISNEY_COOKIE_8='{"query":"mutation refreshToken($input: RefreshTokenInput!) {\n            refreshToken(refreshToken: $input) {\n                activeSession {\n                    sessionId\n                }\n            }\n        }","variables":{"input":{"refreshToken":"ILOVEDISNEY"}}}'

# Result directory for parallel execution
RESULT_DIR="/tmp/ecycloudnode_unlock_check"
RESULT_FILE="/tmp/ecycloudnode_unlock_check_result.json"
LOCK_FILE="/tmp/ecycloudnode_unlock_check.lock"

# Initialize result directory
initResultDir() {
    rm -rf "$RESULT_DIR" 2>/dev/null
    mkdir -p "$RESULT_DIR"
}

# Write individual result to file (thread-safe)
writeResult() {
    local service=$1
    local result=$2
    echo "$result" > "$RESULT_DIR/$service"
}

# Merge all results into final JSON
mergeResults() {
    local youtube_premium=$(cat "$RESULT_DIR/YouTube_Premium" 2>/dev/null || echo "Unknown")
    local netflix=$(cat "$RESULT_DIR/Netflix" 2>/dev/null || echo "Unknown")
    local disney_plus=$(cat "$RESULT_DIR/DisneyPlus" 2>/dev/null || echo "Unknown")
    local hbo_max=$(cat "$RESULT_DIR/HBOMax" 2>/dev/null || echo "Unknown")
    local amazon_prime=$(cat "$RESULT_DIR/AmazonPrime" 2>/dev/null || echo "Unknown")
    local openai=$(cat "$RESULT_DIR/OpenAI" 2>/dev/null || echo "Unknown")
    local gemini=$(cat "$RESULT_DIR/Gemini" 2>/dev/null || echo "Unknown")
    local claude=$(cat "$RESULT_DIR/Claude" 2>/dev/null || echo "Unknown")
    local tiktok=$(cat "$RESULT_DIR/TikTok" 2>/dev/null || echo "Unknown")

    cat > "$RESULT_FILE" << EOF
{
    "YouTube_Premium": "$youtube_premium",
    "Netflix": "$netflix",
    "DisneyPlus": "$disney_plus",
    "HBOMax": "$hbo_max",
    "AmazonPrime": "$amazon_prime",
    "OpenAI": "$openai",
    "Gemini": "$gemini",
    "Claude": "$claude",
    "TikTok": "$tiktok"
}
EOF
}

# Netflix check - improved region detection
UnlockTest_Netflix() {
    local result1=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/81280792' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")
    local result2=$(curl ${CURL_DEFAULT_OPTS} -fsL 'https://www.netflix.com/title/70143836' -w %{http_code} -o /dev/null -H 'host: www.netflix.com' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")

    if [ "${result1}" == '000' ] || [ "$result2" == '000' ]; then
        writeResult "Netflix" "Unknown"
        return
    fi
    if [ "$result1" == '404' ] && [ "$result2" == '404' ]; then
        writeResult "Netflix" "No (Originals Only)"
        return
    fi
    if [ "$result1" == '403' ] || [ "$result2" == '403' ]; then
        writeResult "Netflix" "No"
        return
    fi
    if [ "$result1" == '200' ] || [ "$result2" == '200' ]; then
        local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.netflix.com/' -H 'accept-language: en-US,en;q=0.9' -H "sec-ch-ua: ${UA_SEC_CH_UA}" -H 'sec-ch-ua-mobile: ?0' -H 'sec-ch-ua-platform: "Windows"' -H 'sec-fetch-site: none' -H 'sec-fetch-mode: navigate' -H 'sec-fetch-user: ?1' -H 'sec-fetch-dest: document' --user-agent "${UA_BROWSER}")
        # Extract region from Netflix response
        local region=$(echo "$tmpresult" | grep -oP '"country":"\K[A-Z]{2}' | head -n 1)
        # Fallback to IP-based region detection
        if [ -z "$region" ]; then
            region=$(curl -s --max-time 3 "https://api.country.is" 2>/dev/null | grep -oP '"country":"\K[^"]+')
        fi
        if [ -n "$region" ]; then
            writeResult "Netflix" "Yes ($region)"
        else
            writeResult "Netflix" "Yes"
        fi
        return
    fi
    writeResult "Netflix" "Failed (${result1}_${result2})"
}

# YouTube Premium check
UnlockTest_YouTube_Premium() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.youtube.com/premium' -H 'accept-language: en-US,en;q=0.9' -H 'cookie: YSC=FSCWhKo2Zgw; VISITOR_PRIVACY_METADATA=CgJERRIEEgAgYQ%3D%3D; PREF=f7=4000; __Secure-YEC=CgtRWTBGTFExeV9Iayjele2yBjIKCgJERRIEEgAgYQ%3D%3D; SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY; VISITOR_INFO1_LIVE=Di84mAIbgKY; __Secure-BUCKET=CGQ' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        writeResult "YouTube_Premium" "Unknown"
        return
    fi

    local isCN=$(echo "$tmpresult" | grep 'www.google.cn')
    if [ -n "$isCN" ]; then
        writeResult "YouTube_Premium" "No (CN)"
        return
    fi

    local isNotAvailable=$(echo "$tmpresult" | grep -i 'Premium is not available in your country')
    local region=$(echo "$tmpresult" | grep -woP '"INNERTUBE_CONTEXT_GL"\s{0,}:\s{0,}"\K[^"]+')
    local isAvailable=$(echo "$tmpresult" | grep -i 'ad-free')

    if [ -n "$isNotAvailable" ]; then
        writeResult "YouTube_Premium" "No"
        return
    fi
    if [ -z "$region" ]; then
        region='UNKNOWN'
    fi
    if [ -n "$isAvailable" ]; then
        writeResult "YouTube_Premium" "Yes ($region)"
        return
    fi
    writeResult "YouTube_Premium" "Unknown"
}

# Disney+ check
UnlockTest_DisneyPlus() {
    local PreAssertion=$(curl -4 --user-agent "${UA_Browser}" -s --max-time 8 -X POST "https://disney.api.edge.bamgrid.com/devices" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' 2>&1)
    if [[ "$PreAssertion" == "curl"* ]] || [ -z "$PreAssertion" ]; then
        writeResult "DisneyPlus" "Unknown"
        return
    fi

    local assertion=$(echo $PreAssertion | python -m json.tool 2>/dev/null | grep assertion | cut -f4 -d'"')
    if [ -z "$assertion" ]; then
        assertion=$(echo $PreAssertion | python3 -m json.tool 2>/dev/null | grep assertion | cut -f4 -d'"')
    fi
    local disneycookie=$(echo "$DISNEY_COOKIE_1" | sed "s/DISNEYASSERTION/${assertion}/g")
    local TokenContent=$(curl -4 --user-agent "${UA_Browser}" -s --max-time 8 -X POST "https://disney.api.edge.bamgrid.com/token" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycookie" 2>&1)
    local isBanned=$(echo $TokenContent | grep -i 'forbidden-location')
    local is403=$(echo $TokenContent | grep '403 ERROR')

    if [ -n "$isBanned" ] || [ -n "$is403" ]; then
        writeResult "DisneyPlus" "No"
        return
    fi

    local refreshToken=$(echo $TokenContent | python -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    if [ -z "$refreshToken" ]; then
        refreshToken=$(echo $TokenContent | python3 -m json.tool 2>/dev/null | grep 'refresh_token' | awk '{print $2}' | cut -f2 -d'"')
    fi
    local disneycontent=$(echo "$DISNEY_COOKIE_8" | sed "s/ILOVEDISNEY/${refreshToken}/g")
    local tmpresult=$(curl -4 --user-agent "${UA_Browser}" -X POST -sSL --max-time 8 "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycontent" 2>&1)

    local region=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    if [ -z "$region" ]; then
        region=$(echo $tmpresult | python3 -m json.tool 2>/dev/null | grep 'countryCode' | cut -f4 -d'"')
    fi
    local inSupportedLocation=$(echo $tmpresult | python -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')
    if [ -z "$inSupportedLocation" ]; then
        inSupportedLocation=$(echo $tmpresult | python3 -m json.tool 2>/dev/null | grep 'inSupportedLocation' | awk '{print $2}' | cut -f1 -d',')
    fi

    if [[ "$region" == "JP" ]]; then
        writeResult "DisneyPlus" "Yes (JP)"
        return
    elif [ -n "$region" ] && [[ "$inSupportedLocation" == "true" ]]; then
        writeResult "DisneyPlus" "Yes ($region)"
        return
    elif [ -n "$region" ]; then
        writeResult "DisneyPlus" "No"
        return
    else
        writeResult "DisneyPlus" "Unknown"
        return
    fi
}

# HBO Max check
UnlockTest_HBOMax() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sLi 'https://www.max.com/' -w "_TAG_%{http_code}_TAG_" --user-agent "${UA_Browser}")
    local httpCode=$(echo "$tmpresult" | grep '_TAG_' | awk -F'_TAG_' '{print $2}')
    if [ "$httpCode" == '000' ]; then
        writeResult "HBOMax" "Unknown"
        return
    fi

    local countryList=$(echo "$tmpresult" | grep -woP '"url":"/[a-z]{2}/[a-z]{2}"' | cut -f4 -d'"' | cut -f2 -d'/' | sort -n | uniq | xargs | tr a-z A-Z)
    countryList="${countryList} US"
    local region=$(echo "$tmpresult" | grep -woP 'countryCode=\K[A-Z]{2}' | head -n 1)
    local isUnavailable=$(echo "$countryList" | grep "$region")

    if [ -z "$region" ]; then
        writeResult "HBOMax" "Unknown"
        return
    fi
    if [ -n "$isUnavailable" ]; then
        writeResult "HBOMax" "Yes ($region)"
        return
    fi
    writeResult "HBOMax" "No"
}

# Prime Video check
UnlockTest_PrimeVideo() {
    local tmpresult=$(curl ${CURL_DEFAULT_OPTS} -sL 'https://www.primevideo.com' --user-agent "${UA_BROWSER}")
    if [ -z "$tmpresult" ]; then
        writeResult "AmazonPrime" "Unknown"
        return
    fi

    local isBlocked=$(echo "$tmpresult" | grep -i 'isServiceRestricted')
    local region=$(echo "$tmpresult" | grep -woP '"currentTerritory":"\K[^"]+' | head -n 1)

    if [ -z "$isBlocked" ] && [ -z "$region" ]; then
        writeResult "AmazonPrime" "No"
        return
    fi
    if [ -n "$isBlocked" ]; then
        writeResult "AmazonPrime" "No"
        return
    fi
    if [ -n "$region" ]; then
        writeResult "AmazonPrime" "Yes ($region)"
        return
    fi
    writeResult "AmazonPrime" "No"
}

# OpenAI check
UnlockTest_OpenAI() {
    SUPPORT_COUNTRY=(AL DZ AD AO AG AR AM AU AT AZ BS BD BB BE BZ BJ BT BO BA BW BR BN BG BF CV CA CL CO KM CG CR CI HR CY CZ DK DJ DM DO EC SV EE EG FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT VA HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI KW KG LV LB LS LR LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MA MZ MM NA NR NP NL NZ NI NE NG MK NO OM PK PW PS PA PG PY PE PH PL PT QA RO RW KN LC VC WS SM ST SN RS SC SL SG SK SI SB ZA KR ES LK SR SE CH TW TZ TH TL TG TO TT TN TR TV UG UA AE GB US UY VU ZM)

    local tmpresult1=$(curl ${CURL_DEFAULT_OPTS} -s 'https://api.openai.com/compliance/cookie_requirements' -H 'authorization: Bearer null' --user-agent "${UA_BROWSER}")
    local tmpresult2=$(curl ${CURL_DEFAULT_OPTS} -s 'https://ios.chat.openai.com/' --user-agent "${UA_BROWSER}")

    if [ -z "$tmpresult1" ] || [ -z "$tmpresult2" ]; then
        writeResult "OpenAI" "Unknown"
        return
    fi

    local result1=$(echo "$tmpresult1" | grep -i 'unsupported_country')
    local result2=$(echo "$tmpresult2" | grep -i 'VPN')
    local iso2_code=$(curl -4 -sS --max-time 5 https://chat.openai.com/cdn-cgi/trace 2>/dev/null | grep "loc=" | awk -F= '{print $2}')

    if [ -n "$result1" ] || [ -n "$result2" ] || [ "$iso2_code" == "HK" ] || [ "$iso2_code" == "RU" ]; then
        writeResult "OpenAI" "No"
        return
    fi

    if [ -z "$iso2_code" ]; then
        iso2_code="UNKNOWN"
    fi

    if [[ " ${SUPPORT_COUNTRY[@]} " =~ " ${iso2_code} " ]]; then
        writeResult "OpenAI" "Yes ($iso2_code)"
        return
    else
        writeResult "OpenAI" "No"
        return
    fi
}

# Google Gemini check - region-based detection
# Based on official supported regions: https://ai.google.dev/gemini-api/docs/available-regions
# If YouTube Premium is not available, Gemini is also not available
UnlockTest_Gemini() {
    # Check if YouTube Premium result exists and is "No"
    local ytResult=$(cat "$RESULT_DIR/YouTube_Premium" 2>/dev/null)
    if [[ "$ytResult" == "No"* ]]; then
        writeResult "Gemini" "No"
        return
    fi

    # Gemini supported countries/regions (ISO 3166-1 alpha-2 codes)
    # Source: https://ai.google.dev/gemini-api/docs/available-regions
    GEMINI_SUPPORT_COUNTRY=(AL DZ AS AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BE BZ BJ BM BT BO BA BW BR IO VG BN BG BF CV KH CM CA KY CF TD CL CX CC CO KM CG CK CR CI HR CW CZ CD DK DJ DM DO EC EG SV GQ ER EE SZ ET FK FO FJ FI FR GA GM GE DE GH GI GR GL GD GU GT GG GN GW GY HK HT HN HU IS IN ID IQ IE IM IL IT JM JP JE JO KZ KE KI XK KW KG LA LV LB LS LR LY LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MK MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA CY RO RW BL SH KN LC PM VC WS SM ST SA SN RS SC SL SG SK SI SB SO ZA GS KR SS ES LK SR SE CH TW TJ TZ TH TL TG TK TO TT TN TM TC TV TR UG UA AE GB US UM UY VI UZ VU VE VN WF EH YE ZM ZW AX)

    # Get country code from IP using multiple services
    local iso2_code=$(curl -s --max-time 3 "https://ipinfo.io/country" 2>/dev/null | tr -d '\n')
    if [ -z "$iso2_code" ]; then
        iso2_code=$(curl -s --max-time 3 "https://api.country.is" 2>/dev/null | grep -oE '"country":"[A-Z]{2}"' | sed 's/"country":"//;s/"//')
    fi
    if [ -z "$iso2_code" ]; then
        iso2_code=$(curl -s --max-time 3 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null | tr -d '\n')
    fi

    if [ -z "$iso2_code" ]; then
        writeResult "Gemini" "Unknown"
        return
    fi

    # Check if country is in supported list
    if [[ " ${GEMINI_SUPPORT_COUNTRY[@]} " =~ " ${iso2_code} " ]]; then
        writeResult "Gemini" "Yes ($iso2_code)"
    else
        writeResult "Gemini" "No"
    fi
}

# Claude check - 真实检测 + 官方黑名单兜底
# 主判定：访问 https://claude.ai/，跟随重定向后用最终落地 URL 判断（参考 lmc999/RegionRestrictionCheck）
#   - 落地仍在 claude.ai/   -> 解锁 (Yes)
#   - 落地到 *app-unavailable-in-region (实测为 claude.com 域) -> 不解锁 (No)
# 兜底判定：若主判定 Unknown（HTTP 000 / 落地 URL 无法识别），用官方明确不支持地区黑名单硬判 No
UnlockTest_Claude() {
    # Anthropic 官方明确不支持的国家/地区 (ISO 3166-1 alpha-2) - 兜底用
    # 来源: https://www.anthropic.com/supported-countries (白名单未列出即不支持)
    # CN 中国大陆 / HK 香港 / MO 澳门 / RU 俄罗斯 / BY 白俄罗斯 / IR 伊朗
    # KP 朝鲜 / CU 古巴 / SY 叙利亚 / VE 委内瑞拉 / AF 阿富汗 / MM 缅甸
    CLAUDE_BANNED_COUNTRY=(CN HK MO RU BY IR KP CU SY VE AF MM)

    # 真实检测：同时取 HTTP 状态码与最终落地 URL（双信号判定，规避网络失败时 url_effective 仍输出原 URL 的误判）
    # 注意：curl -w '%{url_effective}' 在 DNS/连接失败时仍会输出请求 URL，必须配合 http_code 才能判别真假
    local probe=$(curl ${CURL_DEFAULT_OPTS} -L -o /dev/null -w '%{http_code}|%{url_effective}' --user-agent "${UA_BROWSER}" 'https://claude.ai/' 2>/dev/null)
    local http_code=$(echo "$probe" | awk -F'|' '{print $1}')
    local final_url=$(echo "$probe" | awk -F'|' '{print $2}')

    # 顺带拿出口国家码用于结果展示（不参与主判定）
    local iso2_code=$(curl ${CURL_DEFAULT_OPTS} 'https://claude.ai/cdn-cgi/trace' --user-agent "${UA_BROWSER}" 2>/dev/null | grep '^loc=' | awk -F= '{print $2}' | tr -d '\r\n')
    if [ -z "$iso2_code" ]; then
        iso2_code=$(curl -s --max-time 3 "https://ipinfo.io/country" 2>/dev/null | tr -d '\r\n ')
    fi
    if [ -z "$iso2_code" ]; then
        iso2_code=$(curl -s --max-time 3 "https://api.country.is" 2>/dev/null | grep -oE '"country":"[A-Z]{2}"' | sed 's/"country":"//;s/"//')
    fi
    if [ -z "$iso2_code" ]; then
        iso2_code=$(curl -s --max-time 3 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null | tr -d '\r\n ')
    fi
    # 严格校验：必须正好 2 个 ASCII 字母，否则视为无效（防止控制字符或异常返回污染输出和黑名单匹配）
    if [ -n "$iso2_code" ]; then
        iso2_code=$(echo "$iso2_code" | tr 'a-z' 'A-Z')
        if ! echo "$iso2_code" | grep -qE '^[A-Z]{2}$'; then
            iso2_code=""
        fi
    fi

    # 主判定：仅当 HTTP 状态码有效（非 000、非空）时，才信任 final_url
    # 关键原则：Anthropic 的地区拦截信号是「跳到 *app-unavailable-in-region*」，
    # 仅看落地 URL，不再以 HTTP 状态码做二次否定。
    # 原因：Cloudflare 反爬会对带 curl 指纹的请求返回 403（URL 不跳转），
    # 该 403 与地区是否支持无关，若以此判 No 会把所有支持地区也错判为 No。
    if [ -n "$http_code" ] && [ "$http_code" != "000" ]; then
        case "$final_url" in
            *app-unavailable-in-region*)
                # 优先匹配不可用页面（避免被前缀通配吃掉）
                writeResult "Claude" "No"
                return
                ;;
            https://claude.ai/*|http://claude.ai/*)
                # 落地仍在 claude.ai：Anthropic 没有对该出口做地区拦截，判为支持
                if [ -n "$iso2_code" ]; then
                    writeResult "Claude" "Yes ($iso2_code)"
                else
                    writeResult "Claude" "Yes"
                fi
                return
                ;;
        esac
    fi

    # 主判定失败（网络异常 / 落地 URL 不可识别）：使用官方黑名单做兜底硬判
    if [ -n "$iso2_code" ]; then
        for banned in "${CLAUDE_BANNED_COUNTRY[@]}"; do
            if [ "$iso2_code" == "$banned" ]; then
                writeResult "Claude" "No"
                return
            fi
        done
    fi

    # 兜底也命中不了 -> Unknown（不带国家码，保持结果简洁）
    writeResult "Claude" "Unknown"
}

# TikTok check - region-based detection
# TikTok is banned or unavailable in certain countries/regions
# Uses blacklist approach similar to OpenAI/Gemini detection
UnlockTest_TikTok() {
    # TikTok banned/unavailable countries (ISO 3166-1 alpha-2 codes)
    # Official government bans:
    #   IN: India (government ban since 2020)
    #   AF: Afghanistan (Taliban ban since 2022)
    #   IR: Iran (long-term ban)
    #   SO: Somalia (government ban since 2023)
    #   SN: Senegal (government ban since 2023)
    #   JO: Jordan (ban since 2022)
    #   UZ: Uzbekistan (ban since 2021)
    #   AL: Albania (ban since 2025, first in Europe)
    #   KG: Kyrgyzstan (ban since 2024)
    # Effectively unavailable:
    #   CN: China mainland (TikTok not available, only Douyin)
    #   HK: Hong Kong (TikTok withdrew from HK in 2020)
    #   KP: North Korea (no internet access)
    TIKTOK_BANNED_COUNTRY=(CN HK IN AF IR SO SN JO UZ AL KG KP)

    # Get country code from IP using multiple services
    local region=$(curl -s --max-time 3 "https://ipinfo.io/country" 2>/dev/null | tr -d '\n')
    if [ -z "$region" ]; then
        region=$(curl -s --max-time 3 "https://api.country.is" 2>/dev/null | grep -oE '"country":"[A-Z]{2}"' | sed 's/"country":"//;s/"//')
    fi
    if [ -z "$region" ]; then
        region=$(curl -s --max-time 3 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null | tr -d '\n')
    fi

    # If we can't determine the region, return Unknown
    if [ -z "$region" ]; then
        writeResult "TikTok" "Unknown"
        return
    fi

    # Convert region to uppercase for comparison
    region=$(echo "$region" | tr 'a-z' 'A-Z')

    # Check if country is in banned list
    if [[ " ${TIKTOK_BANNED_COUNTRY[@]} " =~ " ${region} " ]]; then
        writeResult "TikTok" "No"
        return
    fi

    # TikTok is available in this region
    writeResult "TikTok" "Yes ($region)"
}

# Run all checks in parallel
runCheck() {
    initResultDir

    # First, run YouTube Premium check (Gemini depends on this result)
    UnlockTest_YouTube_Premium &
    local yt_pid=$!

    # Run other checks in parallel (except Gemini)
    UnlockTest_Netflix &
    UnlockTest_DisneyPlus &
    UnlockTest_HBOMax &
    UnlockTest_PrimeVideo &
    UnlockTest_OpenAI &
    UnlockTest_Claude &
    UnlockTest_TikTok &

    # Wait for YouTube Premium to complete before running Gemini
    wait $yt_pid
    UnlockTest_Gemini &

    # Wait for all background processes to complete
    wait

    # Merge results into final JSON
    mergeResults
}

# Main execution
runCheck

# Output result file path
echo "$RESULT_FILE"
`
