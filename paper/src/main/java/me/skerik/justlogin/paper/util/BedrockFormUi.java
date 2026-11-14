package me.skerik.justlogin.paper.util;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.jspecify.annotations.Nullable;

/**
 * Reflection-only wrapper around Floodgate + Cumulus {@code CustomForm} so Bedrock players get native forms
 * when Floodgate is installed, falling back seamlessly to command chat prompts when unavailable.
 */
public final class BedrockFormUi {

    private static volatile boolean initialized;
    private static volatile boolean available;
    private static @Nullable Method sendFormMethod;
    private static @Nullable Method builderMethod;
    private static @Nullable Method titleMethod;
    private static @Nullable Method labelMethod;
    private static @Nullable Method inputMethod;
    private static @Nullable Method buildMethod;
    private static @Nullable Method validConsumerMethod;
    private static @Nullable Method asInputMethod;
    private static @Nullable Object floodgateInstance;

    private BedrockFormUi() {
    }

    public static boolean isAvailable() {
        ensureInit();
        return available;
    }

    public static boolean sendSingleFieldForm(
            UUID playerUuid, String title, String body, String fieldLabel, String placeholder,
            Consumer<String> onSubmit) {
        ensureInit();
        if (!available || floodgateInstance == null) return false;
        try {
            Object builder = builderMethod.invoke(null);
            titleMethod.invoke(builder, title);
            if (!body.isEmpty()) labelMethod.invoke(builder, body);
            inputMethod.invoke(builder, fieldLabel, placeholder);
            attachHandler(builder, resp -> {
                String value = extractInput(resp, 0);
                onSubmit.accept(value);
            });
            Object form = buildMethod.invoke(builder);
            sendFormMethod.invoke(floodgateInstance, playerUuid, form);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean sendTwoFieldForm(
            UUID playerUuid, String title, String body,
            String label1, String placeholder1,
            String label2, String placeholder2,
            BiConsumer<String, String> onSubmit) {
        ensureInit();
        if (!available || floodgateInstance == null) return false;
        try {
            Object builder = builderMethod.invoke(null);
            titleMethod.invoke(builder, title);
            if (!body.isEmpty()) labelMethod.invoke(builder, body);
            inputMethod.invoke(builder, label1, placeholder1);
            inputMethod.invoke(builder, label2, placeholder2);
            attachHandler(builder, resp -> {
                String v1 = extractInput(resp, 0);
                String v2 = extractInput(resp, 1);
                onSubmit.accept(v1, v2);
            });
            Object form = buildMethod.invoke(builder);
            sendFormMethod.invoke(floodgateInstance, playerUuid, form);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void attachHandler(Object builder, Consumer<Object> onResp) throws Exception {
        if (validConsumerMethod.getParameterTypes()[0] == Consumer.class) {
            validConsumerMethod.invoke(builder, onResp);
        } else {
            BiConsumer<Object, Object> bi = (form, resp) -> onResp.accept(resp);
            validConsumerMethod.invoke(builder, bi);
        }
    }

    private static String extractInput(Object resp, int index) {
        try {
            Object val = asInputMethod.invoke(resp, index);
            return val != null ? String.valueOf(val) : "";
        } catch (Throwable t) {
            return "";
        }
    }

    private static void ensureInit() {
        if (initialized) return;
        synchronized (BedrockFormUi.class) {
            if (initialized) return;
            try {
                Class<?> apiCls = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
                floodgateInstance = apiCls.getMethod("getInstance").invoke(null);
                Class<?> formCls = Class.forName("org.geysermc.cumulus.form.Form");
                sendFormMethod = apiCls.getMethod("sendForm", UUID.class, formCls);

                Class<?> customFormCls = Class.forName("org.geysermc.cumulus.form.CustomForm");
                builderMethod = customFormCls.getMethod("builder");
                Class<?> builderCls = Class.forName("org.geysermc.cumulus.form.CustomForm$Builder");
                titleMethod = builderCls.getMethod("title", String.class);
                labelMethod = builderCls.getMethod("label", String.class);
                inputMethod = builderCls.getMethod("input", String.class, String.class);
                buildMethod = builderCls.getMethod("build");

                Class<?> respCls = Class.forName("org.geysermc.cumulus.response.CustomFormResponse");
                asInputMethod = respCls.getMethod("asInput", int.class);

                for (Method m : builderCls.getMethods()) {
                    if ("validResultHandler".equals(m.getName()) && m.getParameterCount() == 1) {
                        Class<?> p = m.getParameterTypes()[0];
                        if (p == Consumer.class || p == BiConsumer.class) {
                            validConsumerMethod = m;
                            if (p == Consumer.class) break;
                        }
                    }
                }
                available = validConsumerMethod != null;
            } catch (Throwable ignored) {
                available = false;
            } finally {
                initialized = true;
            }
        }
    }
}
