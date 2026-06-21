import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";

import { Logo } from "@/components/icons";
import { getVersionInfo } from "@/api";
import { siteConfig, getCachedConfig } from "@/config/site";

interface TabItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  adminOnly?: boolean;
}

export default function H5Layout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [isAdmin, setIsAdmin] = useState(false);
  const [roleId, setRoleId] = useState<number>(1);
  const [showProbe, setShowProbe] = useState(false);
  const [showNetworkMenu, setShowNetworkMenu] = useState(false);
  const [showCenter, setShowCenter] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);

  // 移动端完整菜单配置，底部只固定常用入口，其余放到“更多”
  const menuItems: TabItem[] = [
    {
      path: "/dashboard",
      label: "首页",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z" />
        </svg>
      ),
    },
    {
      path: "/forward",
      label: "转发",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path
            clipRule="evenodd"
            d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z"
            fillRule="evenodd"
          />
        </svg>
      ),
    },
    {
      path: "/subscription",
      label: "订阅中心",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M3 4a1 1 0 011-1h6a1 1 0 010 2H5v10h10v-5a1 1 0 112 0v6a1 1 0 01-1 1H4a1 1 0 01-1-1V4z" />
          <path d="M9 11l6-6 2 2-6 6H9v-2z" />
        </svg>
      ),
    },
    {
      path: "/node",
      label: "节点",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path
            clipRule="evenodd"
            d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11.707 4.707a1 1 0 00-1.414-1.414L10 9.586 8.707 8.293a1 1 0 00-1.414 0l-2 2a1 1 0 101.414 1.414L8 10.414l1.293 1.293a1 1 0 001.414 0l4-4z"
            fillRule="evenodd"
          />
        </svg>
      ),
    },
    {
      path: "/exit",
      label: "出口节点",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M3 5h14v2H3V5zm0 4h10v2H3V9zm0 4h14v2H3v-2z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/easytier",
      label: "组网",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M3 3h4v4H3V3zm5 5h4v4H8V8zm-5 5h4v4H3v-4zm10-10h4v4h-4V3zm0 10h4v4h-4v-4z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/migrate",
      label: "数据迁移",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M4 3h12v4H4V3zm0 6h12v8H4V9zm2 2v4h8v-4H6z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/probe",
      label: "探针目标",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M2 11a1 1 0 011-1h2.586l2-2H8a1 1 0 110-2h1.586l2-2H14a1 1 0 110 2h-.586l-2 2H12a1 1 0 110 2h-.586l-2 2H11a1 1 0 110 2H7a1 1 0 01-1-1v-.586l-2 2V17a1 1 0 11-2 0v-4z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/network",
      label: "网络",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M4 13l3-3 2 2 5-5 2 2v4H4z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/center",
      label: "心跳中心",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M3 10a1 1 0 011-1h2.586l1.707-1.707a1 1 0 011.414 0L10.414 9H13l2-2 3 3-3 3-2-2h-1.586l-1.707 1.707a1 1 0 01-1.414 0L6.414 13H4a1 1 0 01-1-1v-2z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/user",
      label: "用户管理",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z" />
        </svg>
      ),
      adminOnly: true,
    },
    {
      path: "/profile",
      label: "我的",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z" />
        </svg>
      ),
    },
    {
      path: "/config",
      label: "网站配置",
      icon: (
        <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
          <path
            clipRule="evenodd"
            d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z"
            fillRule="evenodd"
          />
        </svg>
      ),
      adminOnly: true,
    },
  ];

  useEffect(() => {
    // 兼容处理：如果没有admin字段，根据role_id判断（0为管理员）
    let adminFlag = localStorage.getItem("admin") === "true";

    if (localStorage.getItem("admin") === null) {
      const roleId = parseInt(localStorage.getItem("role_id") || "1", 10);

      adminFlag = roleId === 0;
      // 补充设置admin字段，避免下次再次判断
      localStorage.setItem("admin", adminFlag.toString());
    }

    setIsAdmin(adminFlag);
    setRoleId(parseInt(localStorage.getItem("role_id") || "1", 10));
    (async () => {
      try {
        const sp = await getCachedConfig("show_probe");
        const sn = await getCachedConfig("show_network");

        setShowProbe(sp === "true");
        setShowNetworkMenu(sn === "true");
      } catch {}
    })();
  }, []);

  useEffect(() => {
    getVersionInfo()
      .then((res: any) => {
        if (res.code === 0 && res.data) {
          setShowCenter(
            res.data.centerOn === true || res.data.center === "true",
          );
        }
      })
      .catch(() => {});
  }, []);

  // Tab点击处理
  const handleTabClick = (path: string) => {
    setMoreOpen(false);
    navigate(path);
  };

  // 过滤tab项（根据权限）
  const filteredMenuItems = menuItems.filter((item) => {
    if (item.path === "/probe" && !showProbe) return false;
    if (item.path === "/network" && !showNetworkMenu) return false;
    if (item.path === "/center" && !showCenter) return false;
    if (roleId === 2 && item.path === "/node")
      return false;

    return !item.adminOnly || isAdmin;
  });
  const primaryPaths = ["/dashboard", "/forward", "/node", "/profile"];
  const primaryPathSet = new Set(primaryPaths);
  const primaryTabItems = primaryPaths
    .map((path) => filteredMenuItems.find((item) => item.path === path))
    .filter((item): item is TabItem => Boolean(item));
  const moreItems = filteredMenuItems.filter(
    (item) => !primaryPathSet.has(item.path),
  );
  const isRouteActive = (path: string) =>
    location.pathname === path || location.pathname.startsWith(`${path}/`);
  const isMoreActive = moreItems.some((item) => isRouteActive(item.path));

  // 路由切换时回到页面顶部，避免上一页的滚动位置遗留
  useEffect(() => {
    setMoreOpen(false);
    try {
      window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    } catch (e) {
      window.scrollTo(0, 0);
    }
    document.body.scrollTop = 0;
    document.documentElement.scrollTop = 0;
  }, [location.pathname]);

  return (
    <div className="flex flex-col min-h-screen bg-gray-100 dark:bg-black">
      {/* 顶部导航栏 */}
      <header className="bg-white dark:bg-black shadow-sm border-b border-gray-200 dark:border-gray-600 h-14 safe-top flex-shrink-0 flex items-center justify-between px-4 relative z-10">
        <div className="flex items-center gap-2">
          <Logo size={20} />
          <h1 className="text-sm font-bold text-foreground">
            {siteConfig.name}
          </h1>
        </div>

        <div className="flex items-center gap-2" />
      </header>

      {/* 主内容区域 */}
      <main className="flex-1 bg-gray-100 dark:bg-black">
        {children}
        {/* Sponsor block above tabbar */}
        <div className="py-2 text-center">
          <a
            aria-label="Sponsor"
            className="inline-block mb-1"
            href="https://vps.town"
            rel="noopener noreferrer"
            target="_blank"
          >
            <img
              alt="Sponsor"
              className="h-8 mx-auto object-contain"
              loading="lazy"
              src="https://vps.town/static/images/sponsor.png"
            />
          </a>
          <p className="text-xs text-gray-400 dark:text-gray-500">
            感谢vps.town提供的服务器赞助
          </p>
        </div>
      </main>

      {/* 用于给固定 Tabbar 腾出空间的占位元素 */}
      <div aria-hidden className="h-16 safe-bottom" />

      {moreOpen && (
        <>
          <button
            aria-label="关闭更多菜单"
            className="fixed inset-0 bg-black/30 dark:bg-black/50 z-40"
            type="button"
            onClick={() => setMoreOpen(false)}
          />
          <section className="fixed left-0 right-0 top-14 bottom-16 z-40 bg-gray-100 dark:bg-black overflow-y-auto border-t border-gray-200 dark:border-gray-700">
            <div className="px-4 py-4">
              <div className="mb-3 flex items-center justify-between">
                <h2 className="text-base font-semibold text-gray-900 dark:text-gray-100">
                  更多
                </h2>
                <button
                  className="px-3 py-2 text-sm text-gray-500 dark:text-gray-400"
                  type="button"
                  onClick={() => setMoreOpen(false)}
                >
                  关闭
                </button>
              </div>
              <div className="grid grid-cols-3 gap-3">
                {moreItems.map((item) => {
                  const isActive = isRouteActive(item.path);

                  return (
                    <button
                      key={item.path}
                      className={`
                        min-h-[84px] rounded-lg border bg-white dark:bg-gray-900
                        flex flex-col items-center justify-center gap-2 px-2 text-center
                        ${
                          isActive
                            ? "border-primary-500 text-primary-600 dark:text-primary-400"
                            : "border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-200"
                        }
                      `}
                      type="button"
                      onClick={() => handleTabClick(item.path)}
                    >
                      <div className="flex-shrink-0">{item.icon}</div>
                      <span className="text-xs font-medium leading-tight">
                        {item.label}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </section>
        </>
      )}

      {/* 底部Tabbar */}
      <nav className="bg-white dark:bg-black border-t border-gray-200 dark:border-gray-600 h-16 safe-bottom flex-shrink-0 flex items-center justify-around px-2 fixed bottom-0 left-0 right-0 z-50">
        {primaryTabItems.map((item) => {
          const isActive = isRouteActive(item.path);

          return (
            <button
              key={item.path}
              className={`
                flex flex-col items-center justify-center flex-1 h-full
                transition-colors duration-200 min-h-[44px]
                ${
                  isActive
                    ? "text-primary-600 dark:text-primary-400"
                    : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
                }
              `}
              onClick={() => handleTabClick(item.path)}
            >
              <div className="flex-shrink-0 mb-1">{item.icon}</div>
              <span className="text-xs font-medium">{item.label}</span>
            </button>
          );
        })}
        {moreItems.length > 0 && (
          <button
            className={`
              flex flex-col items-center justify-center flex-1 h-full
              transition-colors duration-200 min-h-[44px]
              ${
                moreOpen || isMoreActive
                  ? "text-primary-600 dark:text-primary-400"
                  : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
              }
            `}
            type="button"
            onClick={() => setMoreOpen((open) => !open)}
          >
            <div className="flex-shrink-0 mb-1">
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                <path d="M3 5a2 2 0 114 0 2 2 0 01-4 0zm5 0a2 2 0 114 0 2 2 0 01-4 0zm5 0a2 2 0 114 0 2 2 0 01-4 0zM3 15a2 2 0 114 0 2 2 0 01-4 0zm5 0a2 2 0 114 0 2 2 0 01-4 0zm5 0a2 2 0 114 0 2 2 0 01-4 0z" />
              </svg>
            </div>
            <span className="text-xs font-medium">更多</span>
          </button>
        )}
      </nav>
    </div>
  );
}
