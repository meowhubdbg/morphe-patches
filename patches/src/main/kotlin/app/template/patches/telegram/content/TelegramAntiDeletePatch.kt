package app.template.patches.telegram.content

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.template.patches.shared.Constants.TELEGRAM_COMPATIBILITY
import app.template.patches.telegram.signature.telegramSpoofDependency
import app.template.patches.shared.Constants.TELEGRAM_PLUS_COMPATIBILITY
import app.template.patches.shared.Constants.TELEGRAM_WEB_COMPATIBILITY
import app.template.patches.telegram.DeleteMessagesByPushFingerprint
import app.template.patches.telegram.DeleteMessagesByPushFingerprint_13_2_2
import app.template.patches.telegram.MarkMessagesAsDeletedFingerprint1
import app.template.patches.telegram.MarkMessagesAsDeletedFingerprint2
import app.template.patches.telegram.MarkMessagesAsDeletedFingerprint2_13_2_2
import app.template.patches.telegram.NotificationsControllerRemoveDeletedMessagesFingerprint
import app.template.patches.telegram.NotificationsControllerRemoveDeletedMessagesFingerprint_13_2_2

@Suppress("unused")
val telegramAntiDeletePatch = bytecodePatch(
    name = "Anti-delete messages",
    description = "Prevents messages deleted by other users from being removed locally.",
) {
    compatibleWith(TELEGRAM_COMPATIBILITY, TELEGRAM_WEB_COMPATIBILITY, TELEGRAM_PLUS_COMPATIBILITY)
    dependsOn(telegramSpoofDependency())

    execute {
        // 13.2.2 fingerprints verified against the official .web APK
        // (org.telegram.messenger.web, version 13.2.2, versionCode 73039).
        // markMessagesAsDeleted(JIZZ) — p4=Z is the async/local-only flag.
        // true = user-initiated local delete (allow); false = server-push delete (block).
        // 12.x only: the (JIZZ) overload does not exist in official 13.2.2,
        // so probe it and skip silently when missing (known gap on 13.2.2:
        // clear-history push deletes are not guarded there).
        MarkMessagesAsDeletedFingerprint1.methodOrNull?.addInstructions(0, """
            if-nez p4, :allow
            const/4 v0, 0x0
            return-object v0
            :allow
            nop
        """)

        // markMessagesAsDeleted(JArrayListZZII) — p4=Z same semantics.
        // 13.2.2 first (ds.P0, same signature, p4 is still useQueue),
        // 12.x fallback. Loud failure if neither generation matches.
        (MarkMessagesAsDeletedFingerprint2_13_2_2.methodOrNull
            ?: MarkMessagesAsDeletedFingerprint2.method).addInstructions(0, """
            if-nez p4, :allow
            const/4 v0, 0x0
            return-object v0
            :allow
            nop
        """)

        // Block server-push deletion path entirely
        // 13.2.2: sp.c0(JJArrayList), 12.x: deleteMessagesByPush(JArrayListJ).
        (DeleteMessagesByPushFingerprint_13_2_2.methodOrNull
            ?: DeleteMessagesByPushFingerprint.method).addInstructions(0, "return-void")

        // Suppress notification removal when messages are deleted server-side
        // Sig changed in 12.9.2: (LongSparseArray, Z)V
        // 13.2.2: kt.M(La0/h;, Z), 12.x: removeDeletedMessagesFromNotifications.
        (NotificationsControllerRemoveDeletedMessagesFingerprint_13_2_2.methodOrNull
            ?: NotificationsControllerRemoveDeletedMessagesFingerprint.method).addInstructions(0, "return-void")
    }
}
