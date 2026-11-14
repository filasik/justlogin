package me.skerik.justlogin.paper;

import org.bukkit.entity.Entity;
import org.jspecify.annotations.Nullable;

/** The only way this plugin schedules work. Keeps the code ready for Folia's region threads. */
public interface Scheduler {

    void runGlobal(Runnable task);

    void runForEntity(Entity entity, Runnable task, @Nullable Runnable retired);

    void runEntityLater(Entity entity, Runnable task, @Nullable Runnable retired, long delayTicks);

    Runnable runEntityTimer(Entity entity, Runnable task, @Nullable Runnable retired, long delayTicks, long periodTicks);

    void runAsync(Runnable task);

    void runLater(Runnable task, long ticks);

    Runnable runGlobalTimer(Runnable task, long delayTicks, long periodTicks);

    Runnable runAsyncTimer(Runnable task, long delayTicks, long periodTicks);
}
