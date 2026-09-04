# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker (GitHub, `natuan1/vul-hunting`).

| Label in mattpocock/skills | Label in our tracker   | Meaning                                            |
| -------------------------- | ---------------------- | -------------------------------------------------- |
| `needs-triage`             | `Yêu cầu phát triển`   | Issue mới, maintainer cần đánh giá                 |
| `needs-info`               | `Cần thông tin thêm`   | Waiting on reporter for more information           |
| `ready-for-agent`          | `Sẵn sàng cho Agent`   | Fully specified, ready for an AFK agent            |
| `ready-for-human`          | `Cần Human review`     | Requires human implementation / review             |
| `wontfix`                  | `Sẽ không sửa`         | Will not be actioned                               |

## Nhãn phụ (loại issue, dùng kèm nhãn vai trò)

| Label           | Meaning                          |
| --------------- | -------------------------------- |
| `Bug`           | Lỗi trong code/chức năng có sẵn  |
| `Hotfix`        | Bug cần sửa gấp                  |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table — ví dụ "apply the AFK-ready triage label" → `gh issue edit <n> --add-label "Sẵn sàng cho Agent"`.

Edit the right-hand column to match whatever vocabulary you actually use.
