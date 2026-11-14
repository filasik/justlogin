package me.skerik.justlogin.core.service;

import java.util.concurrent.CompletableFuture;

/** Asynchronous email transport abstraction for password recovery codes. */
@FunctionalInterface
public interface EmailSender {
    CompletableFuture<Void> send(String toAddress, String subject, String body);
}
