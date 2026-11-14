package app.template.patches.telegram

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.fieldAccess
import app.morphe.patcher.methodCall
import app.morphe.patcher.string
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

// ════════════════════════════════════════════════════════════════════════════════
// Telegram shared fingerprints
// Verified against: Telegram Web 12.9.2 (69919), TelegramPlus 12.9.0.1 (22437)
// All class names non-obfuscated — stable across Telegram forks.
// AccessFlags omitted where Web/Plus differ (e.g. protected vs public).
// EXCEPTION — Anti-delete on official Telegram 13.2.2: R8 obfuscates the
// messenger classes (ds/sp/kt), so the 13.2.2 fingerprints in the Anti-delete
// section use the obfuscated names (verified against the official 13.2.2 APK).
// ════════════════════════════════════════════════════════════════════════════════

// ─── Premium ──────────────────────────────────────────────────────────────────

val UserConfigIsPremiumFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/UserConfig;",
    name = "isPremium",
    returnType = "Z",
)

val MessagesControllerIsPremiumUserFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isPremiumUser",
    returnType = "Z",
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$User;"),
)

val StoriesControllerIsPremiumFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Stories/StoriesController;",
    name = "isPremium",
    returnType = "Z",
    parameters = listOf("J"),
)

// ─── Integrity bypass ─────────────────────────────────────────────────────────

val AndroidUtilitiesGetCertFingerprintFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/AndroidUtilities;",
    name = "getCertificateSHA256Fingerprint",
    returnType = "Ljava/lang/String;",
)

val SafetyNetCheckFingerprint = Fingerprint(
    filters = listOf(
        string("basicIntegrity"),
        string("ctsProfileMatch"),
    ),
)

// ─── Ads ──────────────────────────────────────────────────────────────────────

val ChatActivityAddSponsoredMessagesFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "addSponsoredMessages",
    returnType = "V",
    parameters = listOf("Z"),
)

val MessagesControllerIsSponsoredDisabledFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isSponsoredDisabled",
    returnType = "Z",
)

val MessageObjectIsSponsoredFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isSponsored",
    returnType = "Z",
)

val VideoAdsLoadFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/video/VideoAds;",
    name = "load",
    returnType = "V",
    accessFlags = listOf(AccessFlags.PRIVATE),
)

// ─── Auto-update ──────────────────────────────────────────────────────────────

val CheckAppUpdateFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/LaunchActivity;",
    name = "checkAppUpdate",
    returnType = "V",
    parameters = listOf("Z", "Lorg/telegram/messenger/browser/Browser\$Progress;"),
)

val BlockingUpdateViewShowFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Components/BlockingUpdateView;",
    name = "show",
    returnType = "V",
    parameters = listOf("I", "Lorg/telegram/tgnet/TLRPC\$TL_help_appUpdate;", "Z"),
)

val SharedConfigIsAppUpdateAvailableFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/SharedConfig;",
    name = "isAppUpdateAvailable",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
)

// Web: setNewAppVersionAvailable(TL_help_appUpdate)Z static
// Plus: same sig — both return Z so returnType = "Z" is safe
val SharedConfigSetNewAppVersionAvailableFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/SharedConfig;",
    name = "setNewAppVersionAvailable",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$TL_help_appUpdate;"),
)

val MessagesControllerCheckPromoInfoInternalFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "checkPromoInfoInternal",
    returnType = "V",
    accessFlags = listOf(AccessFlags.PRIVATE),
    parameters = listOf("Z"),
)

// ─── No-forwards ──────────────────────────────────────────────────────────────

val MessagesControllerIsChatNoForwardsLongFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isChatNoForwards",
    returnType = "Z",
    parameters = listOf("J"),
)

val MessagesControllerIsChatNoForwardsChatFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isChatNoForwards",
    returnType = "Z",
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$Chat;"),
)

val MessagesControllerIsPeerNoForwardsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isPeerNoForwards",
    returnType = "Z",
    parameters = listOf("J"),
)

val ChatActivityIsPeerNoForwardsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "isPeerNoForwards",
    returnType = "Z",
)

val ProfileActivityIsPeerNoForwardsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ProfileActivity;",
    name = "isPeerNoForwards",
    returnType = "Z",
)

val CanForwardMessageFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "canForwardMessage",
    returnType = "Z",
    parameters = listOf(),
)

val ChatActivityHasSelectedNoforwardsMessageFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "hasSelectedNoforwardsMessage",
    returnType = "Z",
)

// ─── Channel restrictions ──────────────────────────────────────────────────────

val GetRestrictionReasonFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "getRestrictionReason",
    returnType = "Ljava/lang/String;",
    parameters = listOf("Ljava/util/ArrayList;"),
)

val MessagesControllerIsSensitiveFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isSensitive",
    returnType = "Z",
    parameters = listOf("Ljava/util/ArrayList;"),
)

// Web: public static; Plus: public (not static). Omit accessFlags for compat.
val ShowCantOpenAlertFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "showCantOpenAlert",
    returnType = "V",
)

val CheckChannelErrorFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "checkChannelError",
    returnType = "V",
    parameters = listOf("Ljava/lang/String;", "J"),
)

val CheckSensitiveFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "checkSensitive",
    returnType = "V",
    parameters = listOf(
        "Lorg/telegram/ui/ActionBar/BaseFragment;",
        "J",
        "Ljava/lang/Runnable;",
        "Ljava/lang/Runnable;",
    ),
)

val ShowSensitiveContentFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "showSensitiveContent",
    returnType = "Z",
    parameters = listOf(),
)

val MessageObjectIsSensitiveFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isSensitive",
    returnType = "Z",
    parameters = listOf(),
)

val MessageObjectIsHiddenSensitiveFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isHiddenSensitive",
    returnType = "Z",
    parameters = listOf(),
)

val CreateNoAccessAlertFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Components/AlertsCreator;",
    name = "createNoAccessAlert",
    returnType = "Lorg/telegram/ui/ActionBar/AlertDialog\$Builder;",
)

val LoadFullChatErrorFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    returnType = "V",
    // 12.9.2: private synthetic lambda, params = (TL_error;J)
    // 12.10.0: R8 promoted to public static synthetic, added MessagesController as first param
    // Omit parameters so both generations match.
    filters = listOf(
        methodCall(
            definingClass = "Lorg/telegram/messenger/MessagesController;",
            name = "checkChannelError",
        ),
    ),
    // R8 name is unstable — exclude the NotificationCenter variant (GetChannelDiff)
    // by ensuring HashSet.remove is present in the body
    // LoadFullChat lambda calls HashSet.remove; GetChannelDiff calls postNotificationName.
    // This distinguishes the two without relying on unstable R8-generated method names.
    custom = { method, _ ->
        method.implementation?.instructions?.any { instr ->
            val ref = (instr as? ReferenceInstruction)?.reference as? MethodReference
            ref?.definingClass == "Ljava/util/HashSet;" && ref.name == "remove"
        } == true
    },
)

val GetChannelDiffErrorFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    returnType = "V",
    // 12.9.2: private synthetic lambda, params = (TL_error;J)
    // 12.10.0: R8 promoted to public static synthetic; params = (MessagesController;TL_error;J)
    // Omit parameters so both generations match.
    filters = listOf(
        methodCall(
            definingClass = "Lorg/telegram/messenger/MessagesController;",
            name = "checkChannelError",
        ),
        methodCall(
            definingClass = "Lorg/telegram/messenger/NotificationCenter;",
            name = "postNotificationName",
        ),
    ),
)

val SetContentSettingsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "setContentSettings",
    returnType = "V",
    parameters = listOf("Z"),
)

val CheckCanOpenChat2Fingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "checkCanOpenChat",
    returnType = "Z",
    parameters = listOf("Landroid/os/Bundle;", "Lorg/telegram/ui/ActionBar/BaseFragment;"),
)

val CheckCanOpenChat3Fingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "checkCanOpenChat",
    returnType = "Z",
    parameters = listOf(
        "Landroid/os/Bundle;",
        "Lorg/telegram/ui/ActionBar/BaseFragment;",
        "Lorg/telegram/messenger/MessageObject;",
    ),
)

val CheckCanOpenChat4Fingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "checkCanOpenChat",
    returnType = "Z",
    parameters = listOf(
        "Landroid/os/Bundle;",
        "Lorg/telegram/ui/ActionBar/BaseFragment;",
        "Lorg/telegram/messenger/MessageObject;",
        "Lorg/telegram/messenger/browser/Browser\$Progress;",
    ),
)

// ─── Anti-delete ──────────────────────────────────────────────────────────────
// 12.x fingerprints below use real class/method names — they match the
// unobfuscated Telegram Web / Telegram Plus forks and official 12.10.1.
// Official Telegram 13.2.2 obfuscates org.telegram.messenger.* with R8, so
// name-based fingerprints CANNOT match it (this is what broke Anti-delete on
// 13.2.2: MessagesStorage/markMessagesAsDeleted no longer exist by name).
// The 13.2.2 fingerprints use the R8-renamed targets, verified by decompiling
// the official 13.2.2 APKs (signature verified) and cross-checked against dex
// method tables. WARNING: the R8 mapping is NOT the same in the two 13.2.2
// builds — same version, same signatures and method bodies, but different
// renamed classes. That is why v1.23.2 (which only had the .web mapping)
// still failed on the Play build:
//   .web (org.telegram.messenger.web, versionCode 73039):
//     MessagesStorage            -> Lorg/telegram/messenger/ds;
//     MessagesController         -> Lorg/telegram/messenger/sp;
//     NotificationsController    -> Lorg/telegram/messenger/kt;
//   Play (org.telegram.messenger, versionCode 73031, APKMirror):
//     MessagesStorage            -> Lorg/telegram/messenger/is;
//     MessagesController         -> Lorg/telegram/messenger/wp;
//     NotificationsController    -> Lorg/telegram/messenger/nt;
//   androidx.collection.LongSparseArray -> La0/h; (same in both builds).
// Each 13.2.2 signature is unique in its class (exactly one method matches).
// The patch resolves Play 13.2.2 first, then .web 13.2.2, then 12.x, so one
// patch serves all generations. Fingerprint1 has NO 13.2.2 equivalent: the
// markMessagesAsDeleted(JIZZ) overload does not exist in 13.2.2 in either
// build (only used by the clear-history push path in 12.x) — known gap.

val MarkMessagesAsDeletedFingerprint1 = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesStorage;",
    name = "markMessagesAsDeleted",
    returnType = "Ljava/util/ArrayList;",
    parameters = listOf("J", "I", "Z", "Z"),
)

val MarkMessagesAsDeletedFingerprint2 = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesStorage;",
    name = "markMessagesAsDeleted",
    returnType = "Ljava/util/ArrayList;",
    parameters = listOf("J", "Ljava/util/ArrayList;", "Z", "Z", "I", "I"),
)

// 13.2.2 .web: MessagesStorage.markMessagesAsDeleted(J, ArrayList, Z, Z, I, I)
// is ds.P0 — identical signature, only the names are R8-renamed.
// p4 is still useQueue, so the patch's guard injection is unchanged.
val MarkMessagesAsDeletedFingerprint2_13_2_2 = Fingerprint(
    definingClass = "Lorg/telegram/messenger/ds;",
    name = "P0",
    returnType = "Ljava/util/ArrayList;",
    parameters = listOf("J", "Ljava/util/ArrayList;", "Z", "Z", "I", "I"),
)

// 13.2.2 Play: same method, same body (if (!z10) return Q0(...) else post
// to the storage queue), but MessagesStorage is is, not ds — verified in
// the Play dex method tables (unique match) and jadx decompilation.
val MarkMessagesAsDeletedFingerprint2_13_2_2_Play = Fingerprint(
    definingClass = "Lorg/telegram/messenger/is;",
    name = "P0",
    returnType = "Ljava/util/ArrayList;",
    parameters = listOf("J", "Ljava/util/ArrayList;", "Z", "Z", "I", "I"),
)

// Web: protected; Plus: public. Omit accessFlags.
val DeleteMessagesByPushFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "deleteMessagesByPush",
    returnType = "V",
    parameters = listOf("J", "Ljava/util/ArrayList;", "J"),
)

// 13.2.2 .web: MessagesController.deleteMessagesByPush(J, ArrayList, J) is
// sp.c0(J, J, ArrayList) — same three values, reordered to
// (dialogId, channelId, ids). Body still posts the delete runnable to the
// storage queue, so return-void at entry still blocks the whole push path.
val DeleteMessagesByPushFingerprint_13_2_2 = Fingerprint(
    definingClass = "Lorg/telegram/messenger/sp;",
    name = "c0",
    returnType = "V",
    parameters = listOf("J", "J", "Ljava/util/ArrayList;"),
)

// 13.2.2 Play: same method as .web sp.c0 (posts the kk runnable, which
// calls is.P0), but MessagesController is wp, not sp — verified via the
// static volatile [Lwp; Instance array, BaseController superclass, and
// jadx decompilation.
val DeleteMessagesByPushFingerprint_13_2_2_Play = Fingerprint(
    definingClass = "Lorg/telegram/messenger/wp;",
    name = "c0",
    returnType = "V",
    parameters = listOf("J", "J", "Ljava/util/ArrayList;"),
)

val NotificationsControllerRemoveDeletedMessagesFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/NotificationsController;",
    name = "removeDeletedMessagesFromNotifications",
    returnType = "V",
    parameters = listOf("Landroidx/collection/LongSparseArray;", "Z"),
)

// 13.2.2 .web: NotificationsController.removeDeletedMessagesFromNotifications
// (LongSparseArray, Z) is kt.M(La0/h;, Z) — a0.h is the R8-renamed
// androidx.collection.LongSparseArray (long[] + Object[] fields, Cloneable).
val NotificationsControllerRemoveDeletedMessagesFingerprint_13_2_2 = Fingerprint(
    definingClass = "Lorg/telegram/messenger/kt;",
    name = "M",
    returnType = "V",
    parameters = listOf("La0/h;", "Z"),
)

// 13.2.2 Play: same method (posts to the notification queue), but
// NotificationsController is nt, not kt — verified via the static volatile
// [Lnt; Instance array, the NotificationManager static field, and jadx.
val NotificationsControllerRemoveDeletedMessagesFingerprint_13_2_2_Play = Fingerprint(
    definingClass = "Lorg/telegram/messenger/nt;",
    name = "M",
    returnType = "V",
    parameters = listOf("La0/h;", "Z"),
)

// ─── Anti-disappearing media ──────────────────────────────────────────────────

val IsSecretMediaInstanceFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isSecretMedia",
    returnType = "Z",
    parameters = listOf(),
)

val IsSecretMediaStaticFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isSecretMedia",
    returnType = "Z",
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$Message;"),
)

val IsSecretPhotoOrVideoFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isSecretPhotoOrVideo",
    returnType = "Z",
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$Message;"),
)

// Static overload (I, Message)Z — present in both Web and Plus.
// Paresh uses this overload. The instance ()Z delegates to this,
// but targeting the static ensures we hit the actual implementation.
val ShouldEncryptPhotoOrVideoFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "shouldEncryptPhotoOrVideo",
    returnType = "Z",
    parameters = listOf("I", "Lorg/telegram/tgnet/TLRPC\$Message;"),
)

val IsVoiceOnceFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isVoiceOnce",
    returnType = "Z",
)

val IsRoundOnceFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isRoundOnce",
    returnType = "Z",
)

// Web: private; Plus: public final. Omit accessFlags.
val SendSecretMediaDeleteFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "sendSecretMediaDelete",
    returnType = "Ljava/lang/Runnable;",
    parameters = listOf("Lorg/telegram/messenger/MessageObject;"),
)

val SendSecretMessageReadFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "sendSecretMessageRead",
    returnType = "Ljava/lang/Runnable;",
    parameters = listOf("Lorg/telegram/messenger/MessageObject;", "Z"),
)

val SecretMediaViewerClosePhotoFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/SecretMediaViewer;",
    name = "closePhoto",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC),
    parameters = listOf("Z", "Z"),
)

// ─── Download boost ───────────────────────────────────────────────────────────

val FileLoadOperationUpdateParamsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/FileLoadOperation;",
    name = "updateParams",
    returnType = "V",
    parameters = listOf(),
)

// ─── Stories / translate / misc premium UI ────────────────────────────────────

val ApplicationLoaderOnCreateFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/ApplicationLoader;",
    name = "onCreate",
    returnType = "V",
    accessFlags = listOf(AccessFlags.PUBLIC),
)

val MessagesControllerStoriesEnabledFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "storiesEnabled",
    returnType = "Z",
)

val MessagesControllerStoryEntitiesAllowedFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "storyEntitiesAllowed",
    returnType = "Z",
    parameters = listOf(),
)

val MessagesControllerStoryEntitiesAllowedUserFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "storyEntitiesAllowed",
    returnType = "Z",
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$User;"),
)

val StoriesControllerHasStoriesFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Stories/StoriesController;",
    name = "hasStories",
    returnType = "Z",
    parameters = listOf(),
)

// Use the 2-param overload (J, StoryItem) — present in both variants
val StoriesControllerMarkStoryAsReadFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Stories/StoriesController;",
    name = "markStoryAsRead",
    returnType = "Z",
    parameters = listOf("J", "Lorg/telegram/tgnet/tl/TL_stories\$StoryItem;"),
)

val PeerStoriesViewAllowScreenshotsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Stories/PeerStoriesView\$StoryItemHolder;",
    name = "allowScreenshots",
    returnType = "Z",
)

val TranslateControllerIsTranslateDialogHiddenFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/TranslateController;",
    name = "isTranslateDialogHidden",
    returnType = "Z",
    parameters = listOf("J"),
)

val ProfileActivityIsSwipeBackEnabledFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ProfileActivity;",
    name = "isSwipeBackEnabled",
    returnType = "Z",
    parameters = listOf("Landroid/view/MotionEvent;"),
)

val ChatActivityIsSwipeBackEnabledFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "isSwipeBackEnabled",
    returnType = "Z",
    parameters = listOf("Landroid/view/MotionEvent;"),
)

val MediaDataControllerLoadPinnedMessagesFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MediaDataController;",
    name = "loadPinnedMessages",
    returnType = "V",
    parameters = listOf("J", "I", "I"),
)

// ─── VoiceToMusic ─────────────────────────────────────────────────────────────

val MessageObjectIsVoiceFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isVoice",
    returnType = "Z",
    parameters = listOf(),
)

val MessageObjectIsMusicFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "isMusic",
    returnType = "Z",
    parameters = listOf(),
    filters = listOf(
        methodCall(
            definingClass = "Lorg/telegram/messenger/MessageObject;",
            name = "isMusicMessage",
        ),
    ),
)

// ─── Anti-disappearing media (additional) ────────────────────────────────────

// MessageObject.needDrawBluredPreview()Z — blurs self-destructing media previews.
// Present in both Web and Plus. Returning false prevents the blurred overlay.
val MessageObjectNeedDrawBluredPreviewFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "needDrawBluredPreview",
    returnType = "Z",
    parameters = listOf(),
)

// ─── Anti-screenshot notification ─────────────────────────────────────────────

// SendMessagesHelper.sendScreenshotMessage(User,I,Message)V
// Notifies the other user when you screenshot a conversation.
val SendScreenshotMessageUserFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/SendMessagesHelper;",
    name = "sendScreenshotMessage",
    returnType = "V",
    parameters = listOf(
        "Lorg/telegram/tgnet/TLRPC\$User;",
        "I",
        "Lorg/telegram/tgnet/TLRPC\$Message;",
    ),
)

// SecretChatHelper.sendScreenshotMessage(EncryptedChat,ArrayList,Message)V
val SendScreenshotMessageSecretFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/SecretChatHelper;",
    name = "sendScreenshotMessage",
    returnType = "V",
    parameters = listOf(
        "Lorg/telegram/tgnet/TLRPC\$EncryptedChat;",
        "Ljava/util/ArrayList;",
        "Lorg/telegram/tgnet/TLRPC\$Message;",
    ),
)

// ─── User no-forwards (missing from original set) ─────────────────────────────

val MessagesControllerIsUserNoForwardsLongFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isUserNoForwards",
    returnType = "Z",
    parameters = listOf("J"),
)

val MessagesControllerIsUserNoForwardsUserFullFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "isUserNoForwards",
    returnType = "Z",
    parameters = listOf("Lorg/telegram/tgnet/TLRPC\$UserFull;"),
)

// ─── Channel switching (Killergram / NoAds) ───────────────────────────────────

// Web: getNextUnreadDialog()Dialog (no params)
// Plus: getNextUnreadDialog(JIIZ[I)Dialog (5 params — different signature)
// Omit parameters for cross-variant compat; method name + returnType + PUBLIC STATIC is unique
val ChatPullingDownDrawableGetNextFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatPullingDownDrawable;",
    name = "getNextUnreadDialog",
    returnType = "Lorg/telegram/tgnet/TLRPC\$Dialog;",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
)

val ChatPullingDownDrawableDrawBottomPanelFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatPullingDownDrawable;",
    name = "drawBottomPanel",
    returnType = "V",
)

val ChatPullingDownDrawableNeedDrawBottomPanelFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatPullingDownDrawable;",
    name = "needDrawBottomPanel",
    returnType = "Z",
)

// ─── Premium account count / device class (Killergram) ───────────────────────

val UserConfigGetMaxAccountCountFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/UserConfig;",
    name = "getMaxAccountCount",
    returnType = "I",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
)

val UserConfigHasPremiumOnAccountsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/UserConfig;",
    name = "hasPremiumOnAccounts",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
)

val SharedConfigGetDevicePerformanceClassFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/SharedConfig;",
    name = "getDevicePerformanceClass",
    returnType = "I",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
)

// ─── Sponsored messages count (NoAds) ────────────────────────────────────────

val ChatActivityGetSponsoredMessagesCountFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "getSponsoredMessagesCount",
    returnType = "I",
    // Web=private, Plus=public final — omit accessFlags for cross-variant compat
)

// MessagesController.getSponsoredMessages(J) — fetches sponsored msg cache entry
val MessagesControllerGetSponsoredMessagesFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "getSponsoredMessages",
    returnType = "Lorg/telegram/messenger/MessagesController\$SponsoredMessagesInfo;",
    accessFlags = listOf(AccessFlags.PUBLIC),
    parameters = listOf("J"),
)

// ─── Copyright / restriction message bypass ───────────────────────────────────

// MessageObject.updateMessageText() — called at construction and on refresh.
// When getRestrictionReason returns non-null, this sets isRestrictedMessage=true
// and replaces messageText with the copyright string.
// Patching getRestrictionReason→null already prevents this, but patching
// updateMessageText directly gives belt-and-suspenders protection.
val MessageObjectUpdateMessageTextFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessageObject;",
    name = "updateMessageText",
    returnType = "V",
    parameters = listOf(),
    accessFlags = listOf(AccessFlags.PUBLIC),
)


// DialogCell.buildLayout()V — calls getRestrictionReason twice; we use matchAll on the
// getRestrictionReason methodCall filter to find and neutralise both result registers.
val DialogCellBuildLayoutFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Cells/DialogCell;",
    name = "buildLayout",
    returnType = "V",
    filters = listOf(
        methodCall(
            definingClass = "Lorg/telegram/messenger/MessagesController;",
            name = "getRestrictionReason",
        ),
    ),
)

// DialogCell.updateMessageThumbs()V — also calls getRestrictionReason
val DialogCellUpdateMessageThumbsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Cells/DialogCell;",
    name = "updateMessageThumbs",
    returnType = "V",
    filters = listOf(
        methodCall(
            definingClass = "Lorg/telegram/messenger/MessagesController;",
            name = "getRestrictionReason",
        ),
    ),
)

// ─── Plus-specific (safe to probe via methodOrNull on non-Plus builds) ────────

// MessagesController.premiumFeaturesBlocked()Z
// Present only in org.telegram.plus — gates "Get Premium" nag dialogs.
// Using methodOrNull makes this safe to reference in shared patches.
val PremiumFeaturesBlockedFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "premiumFeaturesBlocked",
    returnType = "Z",
)

// org.telegram.plus.update.PlusUpdater.checkAppUpdate(RequestDelegate)V
val PlusUpdaterCheckAppUpdateFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/update/PlusUpdater;",
    name = "checkAppUpdate",
    returnType = "V",
)

// PlusSettings.isUpdateEnabled()Z
val PlusSettingsIsUpdateEnabledFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ActionBar/PlusSettings;",
    name = "isUpdateEnabled",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.STATIC),
)

// org.telegram.plus.ads.AdsController.adsDisabled()Z
val AdsControllerAdsDisabledFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/ads/AdsController;",
    name = "adsDisabled",
    returnType = "Z",
)

// org.telegram.plus.ads.AdsInstance.loadAds()V
val AdsInstanceLoadAdsFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/ads/AdsInstance;",
    name = "loadAds",
    returnType = "V",
)

// org.telegram.plus.ads.AdsInstance.loadNativeAd(...) — returns Z in 12.9.0.1
val AdsInstanceLoadNativeAdFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/ads/AdsInstance;",
    name = "loadNativeAd",
    parameters = listOf(
        "Landroid/content/Context;",
        "Z",
        "Lorg/telegram/plus/ads/AdsInstance\$AdsInstanceInterface;",
    ),
)

// MessagesController.sendTyping(JJII)Z — Plus-specific signature
val PlusSendTypingFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/messenger/MessagesController;",
    name = "sendTyping",
    returnType = "Z",
    parameters = listOf("J", "J", "I", "I"),
)

// org.telegram.plus.helpers.AnalyticsHelper fingerprints
val AnalyticsEnableFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/helpers/AnalyticsHelper;",
    name = "enableAnalytics",
    returnType = "V",
    parameters = listOf("Landroid/app/Application;"),
)

val AnalyticsTrackEventFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/helpers/AnalyticsHelper;",
    name = "trackEvent",
    returnType = "V",
    parameters = listOf("Ljava/lang/String;"),
)

val AnalyticsTrackEventMapFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/plus/helpers/AnalyticsHelper;",
    name = "trackEvent",
    returnType = "V",
    parameters = listOf("Ljava/lang/String;", "Ljava/util/HashMap;"),
)

// ─── Rich HTML paste ──────────────────────────────────────────────────────────
val ChatActivityEnterViewHandleRichHtmlPasteFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/Components/ChatActivityEnterView;",
    name = "handleRichHtmlPaste",
    returnType = "Z",
    parameters = listOf(),
)

// ─── Rich-message forwarding / Hide Sender Name ───────────────────────────────
val ChatActivityForwardMessagesFingerprint = Fingerprint(
    definingClass = "Lorg/telegram/ui/ChatActivity;",
    name = "forwardMessages",
    returnType = "V",
    parameters = listOf(
        "Ljava/util/ArrayList;",
        "Z",
        "Z",
        "Z",
        "I",
        "J",
    ),
)