import {
  HomeRegular,
  HomeFilled,
  FolderRegular,
  FolderFilled,
  ArrowSyncRegular,
  ArrowSyncFilled,
  KeyResetRegular,
  KeyResetFilled,
  HistoryRegular,
  HistoryFilled,
  SettingsRegular,
  SettingsFilled,
  InfoRegular,
  InfoFilled,
  LockClosedRegular,
} from "@fluentui/react-icons";
import { api } from "./lib/api";
import { FluentButton, FluentNavigation, FluentSpinner, FluentTooltip, type NavItem } from "./components/fluent";
import { useStore, type Page } from "./lib/store";
import { LoginPage, SetupPage } from "./pages/AuthPages";
import { HomePage } from "./pages/HomePage";
import { FoldersPage } from "./pages/FoldersPage";
import { OperationsPage } from "./pages/OperationsPage";
import { AboutPage, ActivityPage, RecoveryPage, SettingsPage } from "./pages/OtherPages";
import { LockDialog } from "./dialogs/LockDialog";
import { UnlockDialog } from "./dialogs/UnlockDialog";
import { ChangeFolderPasswordDialog, DeleteVaultDialog, DetailsDialog, ErrorsDialog, RemoveOriginalsDialog, ResumeDialog, VerifyDialog, VisibilityDialog } from "./dialogs/VaultDialogs";
import logo from "../src-tauri/icons/32x32.png";

const titles: Record<Page, string> = {
  home: "Home",
  folders: "Protected folders",
  operations: "Active operations",
  recovery: "Recovery",
  activity: "Activity",
  settings: "Settings",
  about: "About",
};

function DialogHost() {
  const { dialog } = useStore();
  if (!dialog) return null;
  switch (dialog.kind) {
    case "lock":
      return <LockDialog key={dialog.path ?? dialog.mode} initialMode={dialog.mode} initialPath={dialog.path} initialHide={dialog.hide} />;
    case "unlock":
      return <UnlockDialog vault={dialog.vault} recovery={dialog.recovery} />;
    case "details":
      return <DetailsDialog vault={dialog.vault} />;
    case "changePassword":
      return <ChangeFolderPasswordDialog vault={dialog.vault} />;
    case "removeOriginals":
      return <RemoveOriginalsDialog vault={dialog.vault} />;
    case "delete":
      return <DeleteVaultDialog vault={dialog.vault} />;
    case "verify":
      return <VerifyDialog vault={dialog.vault} />;
    case "visibility":
      return <VisibilityDialog vault={dialog.vault} hidden={dialog.hidden} />;
    case "resume":
      return <ResumeDialog op={dialog.op} mode={dialog.mode} />;
    case "errors":
      return <ErrorsDialog op={dialog.op} />;
    default:
      return null;
  }
}

export default function App() {
  const { info, unlocked, page, setPage, ops, setUnlocked } = useStore();

  if (!info)
    return (
      <div className="h-full flex items-center justify-center">
        <FluentSpinner size={28} />
      </div>
    );
  if (!info.initialized) return <SetupPage />;
  if (!unlocked) return <LoginPage />;

  const activeCount = ops.filter((o) => o.live).length;
  const attention = ops.filter((o) => !o.live && ["interrupted", "failed", "cancelled"].includes(o.status)).length;
  const items: NavItem<Page>[] = [
    { key: "home", label: "Home", icon: <HomeRegular />, iconSelected: <HomeFilled /> },
    { key: "folders", label: "Protected folders", icon: <FolderRegular />, iconSelected: <FolderFilled /> },
    { key: "operations", label: "Active operations", icon: <ArrowSyncRegular />, iconSelected: <ArrowSyncFilled />, badge: activeCount + attention },
    { key: "recovery", label: "Recovery", icon: <KeyResetRegular />, iconSelected: <KeyResetFilled /> },
    { key: "activity", label: "Activity", icon: <HistoryRegular />, iconSelected: <HistoryFilled /> },
    { key: "settings", label: "Settings", icon: <SettingsRegular />, iconSelected: <SettingsFilled />, footer: true },
    { key: "about", label: "About", icon: <InfoRegular />, iconSelected: <InfoFilled />, footer: true },
  ];

  return (
    <div className="h-full flex">
      <FluentNavigation
        items={items}
        value={page}
        onChange={setPage}
        header={
          <div className="flex items-center gap-3 px-4 h-12">
            <img src={logo} alt="" className="w-5 h-5" />
            <span className="text-[14px] flex-1">DirShield</span>
            <FluentTooltip content="Lock DirShield now">
              <FluentButton
                variant="subtle"
                aria-label="Lock DirShield"
                icon={<LockClosedRegular />}
                onClick={async () => {
                  await api.logout();
                  setUnlocked(false);
                }}
              />
            </FluentTooltip>
          </div>
        }
      />
      <main className="flex-1 min-w-0 h-full overflow-y-auto rounded-tl-[8px] bg-[var(--layer)] border-l border-t border-[var(--stroke-card)]">
        <div key={page} className="anim-page max-w-[1100px] mx-auto px-10 pt-7 pb-10 max-[900px]:px-5">
          <h1 className="t-title font-display mb-6">{titles[page]}</h1>
          {page === "home" && <HomePage />}
          {page === "folders" && <FoldersPage />}
          {page === "operations" && <OperationsPage />}
          {page === "recovery" && <RecoveryPage />}
          {page === "activity" && <ActivityPage />}
          {page === "settings" && <SettingsPage />}
          {page === "about" && <AboutPage />}
        </div>
      </main>
      <DialogHost />
    </div>
  );
}
