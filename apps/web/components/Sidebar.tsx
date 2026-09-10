"use client";

// Sidebar điều hướng chính — client component để dùng usePathname
// đánh dấu mục đang mở. Icon là SVG inline tự vẽ, stroke đồng nhất 1.6.
// Footer là indicator sức khỏe THẬT: poll /api/health (worker + Postgres).

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

type NavItem = {
  href: string;
  label: string;
  icon: ReactNode;
  // "/" khớp tuyệt đối, các mục khác khớp theo tiền tố
  exact?: boolean;
};

function Icon({ children }: { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

const SECTIONS: { label: string; items: NavItem[] }[] = [
  {
    label: "Tổng quan",
    items: [
      {
        href: "/",
        label: "Trạng thái",
        exact: true,
        icon: (
          <Icon>
            <path d="M3 12h4l2.5-6 4 12 2.5-6H21" />
          </Icon>
        ),
      },
    ],
  },
  {
    label: "Săn tìm",
    items: [
      {
        href: "/programs",
        label: "Programs",
        icon: (
          <Icon>
            <path d="M12 3a9 9 0 0 1 9 9M12 7a5 5 0 0 1 5 5M3 21 12 11" />
            <circle cx="12" cy="12" r="1.2" />
          </Icon>
        ),
      },
      {
        href: "/runs",
        label: "Runs",
        icon: (
          <Icon>
            <path d="M5 7l5 5-5 5M12 17h7" />
          </Icon>
        ),
      },
      {
        href: "/findings",
        label: "Findings",
        icon: (
          <Icon>
            <circle cx="12" cy="12" r="6" />
            <path d="M12 5v3M12 16v3M5 12h3M16 12h3" />
          </Icon>
        ),
      },
    ],
  },
  {
    label: "Hệ thống",
    items: [
      {
        href: "/audit",
        label: "Audit",
        icon: (
          <Icon>
            <path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01" />
          </Icon>
        ),
      },
    ],
  },
];

type Health = {
  worker?: { status?: string; postgres?: { connected?: boolean } };
};

// Trạng thái worker: null = đang hỏi, true/false = đã có câu trả lời
function useWorkerHealth(): boolean | null {
  const [ok, setOk] = useState<boolean | null>(null);

  useEffect(() => {
    let live = true;
    const load = () =>
      fetch("/api/health")
        .then((r) => r.json())
        .then((h: Health) => {
          if (live) setOk(h?.worker?.status === "ok");
        })
        .catch(() => {
          if (live) setOk(false);
        });
    load();
    const timer = setInterval(load, 15000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, []);

  return ok;
}

export default function Sidebar() {
  const pathname = usePathname();
  const workerOk = useWorkerHealth();

  const isActive = (item: NavItem) =>
    item.exact ? pathname === item.href : pathname.startsWith(item.href);

  return (
    <aside className="sidebar">
      <Link href="/" className="side-brand">
        <span className="side-glyph">{">_"}</span>
        <span>
          <span className="side-name">vul-hunting</span>
          <span className="side-tag">bug bounty ops</span>
        </span>
      </Link>
      <nav className="side-nav" aria-label="Điều hướng chính">
        {SECTIONS.map((section) => (
          <div key={section.label}>
            <div className="side-label">{section.label}</div>
            {section.items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`side-link${isActive(item) ? " active" : ""}`}
                aria-current={isActive(item) ? "page" : undefined}
              >
                {item.icon}
                {item.label}
              </Link>
            ))}
          </div>
        ))}
      </nav>
      <div className="side-foot">
        <div className="side-status">
          <span
            className={`status-dot${workerOk === false ? " down" : ""}`}
            aria-hidden="true"
          />
          {workerOk === null
            ? "worker · đang kết nối"
            : workerOk
              ? "worker online"
              : "worker offline"}
        </div>
      </div>
    </aside>
  );
}
