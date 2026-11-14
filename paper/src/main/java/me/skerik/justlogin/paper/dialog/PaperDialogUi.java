package me.skerik.justlogin.paper.dialog;

import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import me.skerik.justlogin.paper.config.Messages;
import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.nbt.api.BinaryTagHolder;
import net.kyori.adventure.text.Component;
import org.jspecify.annotations.Nullable;

/**
 * Paper Dialog API (1.21.7–26.x) implementation rendering configuration-phase and play-phase auth modals.
 */
public final class PaperDialogUi implements DialogUi {

    private static final int BODY_WIDTH = 280;
    private static final int INPUT_WIDTH = 220;
    private static final int BUTTON_WIDTH = 130;
    private static final int MAX_INPUT_LEN = 128;

    private final Messages messages;
    private final BooleanSupplier singlePasswordRegister;

    public PaperDialogUi(Messages messages) {
        this(messages, () -> true);
    }

    public PaperDialogUi(Messages messages, BooleanSupplier singlePasswordRegister) {
        this.messages = messages;
        this.singlePasswordRegister = singlePasswordRegister;
    }

    @Override
    public void showRegisterDialog(Audience target, String playerName, int minLen, String nonce, @Nullable Component error) {
        List<DialogBody> body = buildBody(
                messages.component("dialog.register-body", Map.of("player", playerName, "min", String.valueOf(minLen))),
                error);
        List<DialogInput> inputs = singlePasswordRegister.getAsBoolean()
                ? List.of(textInput(ClickData.FIELD_PASSWORD, messages.component("dialog.label-password"), MAX_INPUT_LEN))
                : List.of(
                        textInput(ClickData.FIELD_PASSWORD, messages.component("dialog.label-password"), MAX_INPUT_LEN),
                        textInput(ClickData.FIELD_CONFIRM, messages.component("dialog.label-confirm"), MAX_INPUT_LEN));

        Dialog dialog = buildConfirmation(
                messages.component("dialog.register-title"),
                body,
                inputs,
                messages.component("dialog.btn-register"),
                Clicks.REGISTER,
                nonce);
        target.showDialog(dialog);
    }

    @Override
    public void showLoginDialog(Audience target, String playerName, String nonce, @Nullable Component error) {
        List<DialogBody> body = buildBody(
                messages.component("dialog.login-body", Map.of("player", playerName)),
                error);
        List<DialogInput> inputs = List.of(
                textInput(ClickData.FIELD_PASSWORD, messages.component("dialog.label-password"), MAX_INPUT_LEN));

        Dialog dialog = buildConfirmation(
                messages.component("dialog.login-title"),
                body,
                inputs,
                messages.component("dialog.btn-login"),
                Clicks.LOGIN,
                nonce);
        target.showDialog(dialog);
    }

    @Override
    public void showTotpDialog(Audience target, String nonce, @Nullable Component error) {
        List<DialogBody> body = buildBody(messages.component("dialog.totp-body"), error);
        List<DialogInput> inputs = List.of(
                textInput(ClickData.FIELD_CODE, messages.component("dialog.label-code"), 32));

        Dialog dialog = buildConfirmation(
                messages.component("dialog.totp-title"),
                body,
                inputs,
                messages.component("dialog.btn-verify"),
                Clicks.TOTP,
                nonce);
        target.showDialog(dialog);
    }

    @Override
    public void showForcePasswordChangeDialog(Audience target, int minLen, String nonce, @Nullable Component error) {
        List<DialogBody> body = buildBody(messages.component("dialog.forced-pw-body"), error);
        List<DialogInput> inputs = List.of(
                textInput(ClickData.FIELD_PASSWORD, messages.component("dialog.label-password"), MAX_INPUT_LEN),
                textInput(ClickData.FIELD_CONFIRM, messages.component("dialog.label-confirm"), MAX_INPUT_LEN));

        Dialog dialog = buildConfirmation(
                messages.component("dialog.forced-pw-title"),
                body,
                inputs,
                messages.component("dialog.btn-save"),
                Clicks.FORCE_PW,
                nonce);
        target.showDialog(dialog);
    }

    @Override
    public void close(Audience target) {
        // DialogAfterAction.CLOSE closes client dialogs automatically on action click across MC 1.21.7–26.x.
    }

    private Dialog buildConfirmation(
            Component title,
            List<DialogBody> body,
            List<DialogInput> inputs,
            Component confirmLabel,
            Key confirmKey,
            String nonce) {
        BinaryTagHolder payload = BinaryTagHolder.binaryTagHolder("{nonce:\"" + nonce + "\"}");
        DialogBase base = DialogBase.builder(title)
                .canCloseWithEscape(false)
                .pause(false)
                .afterAction(DialogBase.DialogAfterAction.CLOSE)
                .body(body)
                .inputs(inputs)
                .build();

        ActionButton confirm = ActionButton.create(
                confirmLabel, null, BUTTON_WIDTH, DialogAction.customClick(confirmKey, payload));
        ActionButton cancel = ActionButton.create(
                messages.component("dialog.btn-disconnect"), null, BUTTON_WIDTH,
                DialogAction.customClick(Clicks.CANCEL, payload));

        return Dialog.create(factory -> factory.empty()
                .base(base)
                .type(DialogType.confirmation(confirm, cancel)));
    }

    private static List<DialogBody> buildBody(Component intro, @Nullable Component error) {
        List<DialogBody> body = new ArrayList<>(2);
        body.add(DialogBody.plainMessage(intro, BODY_WIDTH));
        if (error != null) {
            body.add(DialogBody.plainMessage(error, BODY_WIDTH));
        }
        return body;
    }

    private static DialogInput textInput(String key, Component label, int maxLen) {
        return DialogInput.text(key, label)
                .width(INPUT_WIDTH)
                .labelVisible(true)
                .initial("")
                .maxLength(maxLen)
                .build();
    }
}
