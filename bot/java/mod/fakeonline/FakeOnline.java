package com.fakeonline;

import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.World;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.ArmorStand;
import org.bukkit.entity.Player;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.SkullMeta;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scoreboard.Scoreboard;
import org.bukkit.scoreboard.Team;
import org.bukkit.util.EulerAngle;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

/**
 * FakeOnline — standalone Bukkit/Spigot plugin that fakes a player presence.
 * Fake "players" (ArmorStand NPCs with player-skin heads) stand at an anchor
 * point and idle-AFK. A tab-list header shows an inflated online count so the
 * server looks busier than it is.
 *
 * Commands (op):
 *   /fko add <n>       spawn n fake players
 *   /fko remove <n>    despawn n of them
 *   /fko clear         despawn all
 *   /fko loc           set anchor at sender's current position
 *   /fko list          list fake players
 *   /fko reload        reload config and respawn
 *
 * Pure Bukkit API — no NMS, compiles against spigot-api 1.20.x.
 * NOTE: the server's *real* /list count cannot be inflated without NMS
 * (player_info injection). This fakes the visuals + the tab header count.
 */
public final class FakeOnline extends JavaPlugin implements CommandExecutor {

    private static final String[] SKINS = {
        "Steve", "Alex", "Herobrine", "Mumbo", "Technoblade", "Ph1LzA", "Dream",
        "GeorgeNotFound", "Sapnap", "Tubbo", "TommyInnit", "Ranboo", "Wilbur",
        "Niki", "Benn,", "DanTDM", "PewDiePie", "jeb_", "Notch", "Dinnerbone",
    };

    private final Random rnd = new Random();
    private final Map<String, ArmorStand> npcs = new HashMap<>();

    private String headerPrefix;
    private int fakeBase;
    private Location anchor;
    private BukkitRunnable idleTask;
    private Scoreboard board;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        FileConfiguration c = getConfig();
        headerPrefix = c.getString("tab.prefix", "&7[&aOnline&7] &f");
        fakeBase = Math.max(0, c.getInt("fake.count", 0));
        int fx = c.getInt("anchor.x", 0);
        int fy = c.getInt("anchor.y", 0);
        int fz = c.getInt("anchor.z", 0);
        String worldName = c.getString("anchor.world", "world");
        World anchorWorld = Bukkit.getWorld(worldName);
        if (anchorWorld != null) {
            anchor = new Location(anchorWorld, fx + 0.5, fy, fz + 0.5);
        }

        getCommand("fko").setExecutor(this);

        board = Bukkit.getScoreboardManager().getMainScoreboard();

        ensureAnchor();
        if (anchor == null) {
            getLogger().warning("FakeOnline anchor unset; set with /fko loc or anchor.* in config");
        } else {
            // Self-start: at least one fake player stands immediately on boot.
            spawnAll(Math.max(1, c.getInt("fake.count", 1)));
        }
        startIdleAnim();
        refreshTab();
    }

    @Override
    public void onDisable() {
        if (idleTask != null) { idleTask.cancel(); idleTask = null; }
        despawnAll();
    }

    // ---------------------------------------------------------------- commands

    @Override
    public boolean onCommand(CommandSender s, Command cmd, String label, String[] args) {
        if (args.length == 0) { help(s); return true; }
        switch (args[0].toLowerCase()) {
            case "add": {
                int n = parseInt(args, 1, 1);
                ensureAnchor();
                if (anchor == null) { s.sendMessage("§cNo world/anchor available."); break; }
                int before = npcs.size();
                spawn(n);
                setCount(before + n);
                s.sendMessage("§aFake online §e" + before + " §a-> §e" + npcs.size());
                break;
            }
            case "remove": {
                int n = parseInt(args, 1, 1);
                int before = npcs.size();
                int removed = despawn(n);
                setCount(Math.max(0, before - n));
                s.sendMessage("§aRemoved §e" + removed + " §afake players §e(" + npcs.size() + " left)");
                break;
            }
            case "clear": {
                despawnAll();
                setCount(0);
                s.sendMessage("§aAll fake players cleared.");
                break;
            }
            case "loc": {
                if (!(s instanceof Player)) {
                    s.sendMessage("§cConsole can't /loc — set anchor.* in config.yml or run it in-game.");
                    break;
                }
                Player p = (Player) s;
                setAnchor(p.getLocation());
                s.sendMessage("§aAnchor set at §6"
                    + anchor.getBlockX() + " " + anchor.getBlockY() + " " + anchor.getBlockZ());
                break;
            }
            case "list": {
                s.sendMessage("§7Fake online: §e" + npcs.size());
                for (String n : npcs.keySet()) s.sendMessage("  §f" + n);
                break;
            }
            case "reload": {
                reloadConfig();
                despawnAll();
                setCount(0);
                anchor = null;
                ensureAnchor();
                if (anchor != null) spawnAll(Math.max(1, getConfig().getInt("fake.count", 1)));
                s.sendMessage("§aReloaded.");
                break;
            }
            default:
                help(s);
        }
        refreshTab();
        return true;
    }

    private void help(CommandSender s) {
        s.sendMessage("§b== FakeOnline ==\n" +
            "§f/fko add <n>§7 — spawn\n" +
            "§f/fko remove <n>§7 — despawn\n" +
            "§f/fko clear§7 — all off\n" +
            "§f/fko loc§7 — set anchor here (in-game)\n" +
            "§f/fko list / reload");
    }

    // Fallback anchor for console-driven ops and self-start: main world spawn.
    private void ensureAnchor() {
        if (anchor != null) return;
        World w = Bukkit.getWorld(getConfig().getString("anchor.world", "world"));
        if (w == null && !Bukkit.getWorlds().isEmpty()) w = Bukkit.getWorlds().get(0);
        if (w != null && w.getSpawnLocation() != null) {
            anchor = w.getSpawnLocation().clone().add(0.5, 1.0, 0.5);
        }
    }

    // ---------------------------------------------------------------- spawn

    private void spawn(int n) {
        for (int i = 0; i < n; i++) {
            String name = freshName();
            if (name == null) return;
            spawnNpc(name);
        }
    }

    private void spawnAll(int n) {
        despawnAll();
        for (int i = 0; i < n; i++) spawn(1);
        setCount(npcs.size());
    }

    private void spawnNpc(String name) {
        if (npcs.containsKey(name)) return;
       // Offset each NPC a little so they don't stack perfectly.
        double ox = (rnd.nextDouble() - 0.5) * 4.0;
        double oz = (rnd.nextDouble() - 0.5) * 4.0;
        Location pos = anchor.clone().add(ox, -1.05, oz).clone();
        pos.setYaw(rnd.nextInt(360));

        ArmorStand as = anchor.getWorld().spawn(pos, ArmorStand.class);
        as.setVisible(false);
        as.setMarker(true);
        as.setSmall(false);
        as.setGravity(true);
        as.setBasePlate(false);
        as.setArms(false);
        as.setCustomNameVisible(true);
        as.setCustomName("§e" + name);
        as.getEquipment().setHelmet(skinHead(name));
        colorTeam(name);

        npcs.put(name, as);
    }

    private ItemStack skinHead(String name) {
        ItemStack head = new ItemStack(Material.PLAYER_HEAD);
        SkullMeta meta = (SkullMeta) head.getItemMeta();
        if (meta != null) {
            try { meta.setOwningPlayer(Bukkit.getOfflinePlayer(name)); } catch (Throwable t) {}
            head.setItemMeta(meta);
        }
        return head;
    }

    private void colorTeam(String name) {
        Team team = board.getTeam("fo_" + Math.abs(name.hashCode() % 10000));
        if (team == null) team = board.registerNewTeam("fo_" + Math.abs(name.hashCode() % 10000));
        team.setPrefix("§7");
        team.addEntry(name);
    }

    private String freshName() {
        for (int attempt = 0; attempt < 200; attempt++) {
            String base = SKINS[rnd.nextInt(SKINS.length)];
            String name = base + "_" + (1000 + rnd.nextInt(9000));
            if (name.length() > 16) name = name.substring(0, 16);
            if (!npcs.containsKey(name)) return name;
        }
        return null;
    }

    private int despawn(int n) {
        int removed = 0;
        List<String> keys = new ArrayList<>(npcs.keySet());
        for (String k : keys) {
            if (removed >= n) break;
            ArmorStand as = npcs.remove(k);
            if (as != null) { as.remove(); removed++; }
        }
        return removed;
    }

    private void despawnAll() {
        for (ArmorStand as : npcs.values()) {
            try { as.remove(); } catch (Throwable ignored) {}
        }
        npcs.clear();
    }

    // ---------------------------------------------------------------- config

    private void setCount(int n) {
        fakeBase = Math.max(0, n);
        getConfig().set("fake.count", fakeBase);
        saveConfig();
    }

    private void setAnchor(Location l) {
        anchor = l;
        getConfig().set("anchor.world", l.getWorld().getName());
        getConfig().set("anchor.x", l.getBlockX());
        getConfig().set("anchor.y", l.getBlockY());
        getConfig().set("anchor.z", l.getBlockZ());
        saveConfig();
    }

    private Location readAnchor(Location fallback) {
        World w = Bukkit.getWorld(getConfig().getString("anchor.world", "world"));
        if (w == null) return null;
        return new Location(w,
            getConfig().getInt("anchor.x", 0) + 0.5,
            getConfig().getInt("anchor.y", 0),
            getConfig().getInt("anchor.z", 0) + 0.5);
    }

    private int parseInt(String[] args, int i, int def) {
        if (args.length > i) {
            try { return Integer.parseInt(args[i]); } catch (NumberFormatException e) {}
        }
        return def;
    }

    // ---------------------------------------------------------------- anim + tab

    private void startIdleAnim() {
        idleTask = new BukkitRunnable() {
            int tick = 0;
            @Override public void run() {
                tick++;
                for (ArmorStand as : npcs.values()) {
                    if (as == null || as.isDead()) continue;
                    // Gentle idle: slow head sway + a soft bob every so often.
                    EulerAngle p = as.getHeadPose();
                    as.setHeadPose(new EulerAngle(
                        p.getX() + 0.001, (tick * 0.02) % 6.283, p.getZ()));
                    if (tick % 120 == 0) {
                        as.setVelocity(as.getVelocity().clone().setY(0.15));
                    }
                }
                if (tick % 200 == 0) refreshTab();
            }
        };
        idleTask.runTaskTimer(this, 2L, 2L);
    }

    private void refreshTab() {
        // Inflated fake-online counter in the tab header: real + fake.
        int real = Bukkit.getOnlinePlayers().size();
        int total = real + npcs.size();
        String header = color(headerPrefix + "&e" + total + "&7 online"
            + "&8  (&7" + real + " real &8/ &7" + npcs.size() + " fake&8)");
        String footer = color("&7&oFakeOnline");
        for (Player p : Bukkit.getOnlinePlayers()) {
            p.setPlayerListHeaderFooter(header, footer);
        }
    }

    private static String color(String s) {
        return s.replace("&", "§");
    }
}