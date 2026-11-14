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
import logo from "../../src-tauri/icons/32x32.png";
import { api } from "@/api";
import { useStore, type Page } from "@/app/store";
import { FluentButton, FluentNavigation, FluentSpinner, FluentTooltip, type NavItem } from "@/components/fluent";
import { AboutPage } from "@/features/about/AboutPage";
import { ActivityPage } from "@/features/activity/ActivityPage";
import { LoginPage } from "@/features/auth/LoginPage";
import { SetupPage } from "@/features/auth/SetupPage";
import { FoldersPage } from "@/features/folders/FoldersPage";
import { ChangeFolderPasswordDialog } from "@/features/folders/dialogs/ChangeFolderPasswordDialog";
import { DeleteVaultDialog } from "@/features/folders/dialogs/DeleteVaultDialog";
import { DetailsDialog } from "@/features/folders/dialogs/DetailsDialog";
import { LockDialog } from "@/features/folders/dialogs/LockDialog";
import { RemoveOriginalsDialog } from "@/features/folders/dialogs/RemoveOriginalsDialog";
import { UnlockDialog } from "@/features/folders/dialogs/UnlockDialog";
import { VerifyDialog } from "@/features/folders/dialogs/VerifyDialog";
import { VisibilityDialog } from "@/features/folders/dialogs/VisibilityDialog";
import { HomePage } from "@/features/home/HomePage";
import { OperationsPage } from "@/features/operations/OperationsPage";
import { ErrorsDialog } from "@/features/operations/dialogs/ErrorsDialog";
import { ResumeDialog } from "@/features/operations/dialogs/ResumeDialog";
import { RecoveryPage } from "@/features/recovery/RecoveryPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { UpdateBanner, useAutoUpdateCheck } from "@/features/updates/updater";

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
  const { info, unlocked, page, setPage, ops, setUnlocked, dragging } = useStore();
  useAutoUpdateCheck();

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
          <UpdateBanner />
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
      {dragging && page !== "home" && (
        <div className="fixed inset-3 z-50 pointer-events-none rounded-[8px] border-2 border-dashed border-[var(--accent)] bg-[var(--layer)]/80 flex flex-col items-center justify-center gap-2">
          <LockClosedRegular fontSize={40} className="text-[var(--accent)]" />
          <div className="t-subtitle font-display">Drop to protect this folder</div>
          <div className="text-[var(--text-2)]">You'll choose Quick Lock or Secure Lock next.</div>
        </div>
      )}
    </div>
  );
}
