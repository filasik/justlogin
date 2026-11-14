package me.skerik.justlogin.paper;

import io.papermc.paper.threadedregions.scheduler.ScheduledTask;
import java.util.concurrent.TimeUnit;
import org.bukkit.Bukkit;
import org.bukkit.entity.Entity;
import org.bukkit.plugin.Plugin;
import org.jspecify.annotations.Nullable;

/** Scheduler on Paper's region-style schedulers (Folia-compatible). */
public final class PaperScheduler implements Scheduler {

    private static final long TICK_MS = 50;

    private final Plugin plugin;

    public PaperScheduler(Plugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void runGlobal(Runnable task) {
        if (!plugin.isEnabled()) return;
        Bukkit.getGlobalRegionScheduler().run(plugin, t -> task.run());
    }

    @Override
    public void runForEntity(Entity entity, Runnable task, @Nullable Runnable retired) {
        if (!plugin.isEnabled()) return;
        entity.getScheduler().run(plugin, t -> task.run(), retired);
    }

    @Override
    public void runEntityLater(Entity entity, Runnable task, @Nullable Runnable retired, long delayTicks) {
        if (!plugin.isEnabled()) return;
        entity.getScheduler().runDelayed(plugin, t -> task.run(), retired, Math.max(1, delayTicks));
    }

    @Override
    public Runnable runEntityTimer(Entity entity, Runnable task, @Nullable Runnable retired, long delayTicks, long periodTicks) {
        if (!plugin.isEnabled()) return () -> {};
        ScheduledTask handle = entity.getScheduler().runAtFixedRate(
                plugin, t -> task.run(), retired, Math.max(1, delayTicks), Math.max(1, periodTicks));
        return handle == null ? () -> {} : handle::cancel;
    }

    @Override
    public void runAsync(Runnable task) {
        if (!plugin.isEnabled()) return;
        Bukkit.getAsyncScheduler().runNow(plugin, t -> task.run());
    }

    @Override
    public void runLater(Runnable task, long ticks) {
        if (!plugin.isEnabled()) return;
        Bukkit.getGlobalRegionScheduler().runDelayed(plugin, t -> task.run(), Math.max(1, ticks));
    }

    @Override
    public Runnable runGlobalTimer(Runnable task, long delayTicks, long periodTicks) {
        ScheduledTask handle = Bukkit.getGlobalRegionScheduler()
                .runAtFixedRate(plugin, t -> task.run(), Math.max(1, delayTicks), Math.max(1, periodTicks));
        return handle::cancel;
    }

    @Override
    public Runnable runAsyncTimer(Runnable task, long delayTicks, long periodTicks) {
        ScheduledTask handle = Bukkit.getAsyncScheduler().runAtFixedRate(plugin, t -> task.run(),
                Math.max(1, delayTicks) * TICK_MS, Math.max(1, periodTicks) * TICK_MS, TimeUnit.MILLISECONDS);
        return handle::cancel;
    }
}
