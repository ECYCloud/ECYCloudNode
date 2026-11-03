#!/usr/bin/env bash
# 上传文件到 Release，已发布的文件不覆盖，供重试步骤反复调用：
# 同名资产已传完且 sha256 一致，视为前一次尝试已上传，跳过；内容不同时以退出码 3 拒绝；未传完的残留资产先删除再传。
# 用法：upload-release-assets.sh <tag> <文件>...
set -euo pipefail

tag="$1"
shift
release_id="$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" --jq .id)"
for file in "$@"; do
    name="${file##*/}"
    asset="$(gh api --paginate "repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets" \
        --jq ".[] | select(.name == \"${name}\") | \"\(.id) \(.state) \(.digest)\"")"
    if [[ -n "${asset}" ]]; then
        read -r id state digest <<< "${asset}"
        if [[ "${state}" == uploaded ]]; then
            if [[ "${digest}" == "sha256:$(sha256sum "${file}" | cut -d' ' -f1)" ]]; then
                continue
            fi
            echo "Release ${tag} 中已发布的 ${name} 与本次构建不同，拒绝覆盖" >&2
            exit 3
        fi
        gh api -X DELETE "repos/${GITHUB_REPOSITORY}/releases/assets/${id}"
    fi
    gh release upload "${tag}" "${file}" --repo "${GITHUB_REPOSITORY}"
done
