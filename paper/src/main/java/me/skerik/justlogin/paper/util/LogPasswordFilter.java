package me.skerik.justlogin.paper.util;

import java.util.regex.Pattern;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;
import org.jspecify.annotations.Nullable;

/**
 * Prevents passwords, TOTP setup tokens, and admin password-change arguments from leaking into server logs
 * (Threat model #10).
 */
public final class LogPasswordFilter extends AbstractFilter {

    private static final Pattern SENSITIVE_COMMAND_LOG = Pattern.compile(
            "(?i).*issued server command:\\s*/(?:[a-z0-9_-]+:)?("
                    + "login|l|register|reg|changepassword|changepass|cp|unregister|cracked|2fa|email\\s+(?:recover|set|confirm)"
                    + "|(?:justlogin|jl|auth)\\s+(?:changepassword|changepass|import\\s+\\S+\\s+mysql|applyedits)"
                    + ")\\b.*"
    );

    private LogPasswordFilter() {
    }

    public static boolean isSensitiveCommandLog(@Nullable String formattedMessage) {
        if (formattedMessage == null || formattedMessage.isEmpty()) return false;
        return SENSITIVE_COMMAND_LOG.matcher(formattedMessage).matches();
    }

    public static LogPasswordFilter installOnRoot() {
        LogPasswordFilter filter = new LogPasswordFilter();
        filter.start();
        org.apache.logging.log4j.Logger root = LogManager.getRootLogger();
        if (root instanceof Logger coreLogger) {
            coreLogger.addFilter(filter);
        }
        return filter;
    }

    public void uninstallFromRoot() {
        stop();
        org.apache.logging.log4j.Logger root = LogManager.getRootLogger();
        if (root instanceof Logger coreLogger) {
            coreLogger.get().removeFilter(this);
            coreLogger.getContext().updateLoggers();
        }
    }

    @Override
    public Result filter(LogEvent event) {
        if (!isStarted() || event == null || event.getMessage() == null) return Result.NEUTRAL;
        return isSensitiveCommandLog(event.getMessage().getFormattedMessage()) ? Result.DENY : Result.NEUTRAL;
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Message msg, Throwable t) {
        if (!isStarted() || msg == null) return Result.NEUTRAL;
        return isSensitiveCommandLog(msg.getFormattedMessage()) ? Result.DENY : Result.NEUTRAL;
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Object msg, Throwable t) {
        if (!isStarted() || msg == null) return Result.NEUTRAL;
        return isSensitiveCommandLog(String.valueOf(msg)) ? Result.DENY : Result.NEUTRAL;
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, String msg, Object... params) {
        if (!isStarted() || msg == null) return Result.NEUTRAL;
        if (isSensitiveCommandLog(msg)) return Result.DENY;
        if (params != null && params.length > 0 && msg.contains("issued server command:")) {
            // Also check parameterized formatting when Bukkit/Paper logs with {}
            String combined = org.apache.logging.log4j.message.ParameterizedMessage.format(msg, params);
            if (isSensitiveCommandLog(combined)) return Result.DENY;
        }
        return Result.NEUTRAL;
    }
}
