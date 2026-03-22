// TokenSnipe — License Server v4
// New commands: /pausekey, /resumekey, /activeusers, /transferkey, /addnote, /whois, /bulkrevoke

const express   = require('express');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const { MongoClient } = require('mongodb');
const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } = require('discord.js');

const app  = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET    = process.env.JWT_SECRET;
const ADMIN_KEY     = process.env.ADMIN_KEY;
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const DISCORD_GUILD = process.env.DISCORD_GUILD;
const DISCORD_ROLE  = process.env.DISCORD_ROLE;

if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET not set'); process.exit(1); }
if (!ADMIN_KEY)  { console.error('FATAL: ADMIN_KEY not set');  process.exit(1); }

// Minimum app version — set MIN_VERSION in Railway variables to force updates
// Old builds that don't send x-app-version will be rejected automatically
const MIN_VERSION = parseInt(process.env.MIN_VERSION || '2');

// ── DISCORD BOT ───────────────────────────────────────────────────────────
if (DISCORD_TOKEN && DISCORD_GUILD && DISCORD_ROLE) {

  const client = new Client({ intents: [GatewayIntentBits.Guilds] });

  const DURATION_CHOICES = [
    { name: '1 hour',    value: 'h1'   }, { name: '2 hours',   value: 'h2'   },
    { name: '3 hours',   value: 'h3'   }, { name: '6 hours',   value: 'h6'   },
    { name: '12 hours',  value: 'h12'  }, { name: '18 hours',  value: 'h18'  },
    { name: '24 hours',  value: 'h24'  }, { name: '1 day',     value: 'd1'   },
    { name: '3 days',    value: 'd3'   }, { name: '7 days',    value: 'd7'   },
    { name: '14 days',   value: 'd14'  }, { name: '30 days',   value: 'd30'  },
    { name: '1 month',   value: 'm1'   }, { name: '2 months',  value: 'm2'   },
    { name: '3 months',  value: 'm3'   }, { name: '6 months',  value: 'm6'   },
    { name: '12 months', value: 'm12'  }, { name: 'Lifetime',  value: 'lifetime' },
  ];

  const commands = [
    // ── EXISTING ──────────────────────────────────────────────────────
    new SlashCommandBuilder()
      .setName('genkey')
      .setDescription('Generate a new TokenSnipe license key')
      .addStringOption(o => o.setName('note').setDescription('Who is this key for?').setRequired(false))
      .addStringOption(o => o.setName('duration').setDescription('How long?').setRequired(false).addChoices(...DURATION_CHOICES)),

    new SlashCommandBuilder()
      .setName('revokekey')
      .setDescription('Revoke a license key')
      .addStringOption(o => o.setName('key').setDescription('The key to revoke').setRequired(true)),

    new SlashCommandBuilder()
      .setName('reactivate')
      .setDescription('Reactivate a revoked key')
      .addStringOption(o => o.setName('key').setDescription('The key to reactivate').setRequired(true)),

    new SlashCommandBuilder()
      .setName('keyinfo')
      .setDescription('Look up full info + live countdown on a key')
      .addStringOption(o => o.setName('key').setDescription('The key to look up').setRequired(true)),

    new SlashCommandBuilder()
      .setName('resetwid')
      .setDescription('Reset the HWID lock so a key can be used on a new device')
      .addStringOption(o => o.setName('key').setDescription('The key to reset').setRequired(true)),

    new SlashCommandBuilder()
      .setName('deletekey')
      .setDescription('Permanently delete a key')
      .addStringOption(o => o.setName('key').setDescription('The key to delete').setRequired(true)),

    new SlashCommandBuilder()
      .setName('extendkey')
      .setDescription('Add more time to an existing key')
      .addStringOption(o => o.setName('key').setDescription('The key to extend').setRequired(true))
      .addStringOption(o => o.setName('duration').setDescription('How much time to add').setRequired(true).addChoices(...DURATION_CHOICES.filter(c => c.value !== 'lifetime'))),

    new SlashCommandBuilder()
      .setName('listkeys')
      .setDescription('List keys by status')
      .addStringOption(o => o.setName('filter').setDescription('Which keys to show').setRequired(false)
        .addChoices(
          { name: 'Active',   value: 'active'  },
          { name: 'Pending',  value: 'pending' },
          { name: 'Revoked',  value: 'revoked' },
          { name: 'Expired',  value: 'expired' },
          { name: 'Paused',   value: 'paused'  },
          { name: 'All',      value: 'all'     },
        )),

    new SlashCommandBuilder()
      .setName('listnotes')
      .setDescription('Search keys by note or key string')
      .addStringOption(o => o.setName('search').setDescription('Search term').setRequired(false)),

    new SlashCommandBuilder()
      .setName('stats')
      .setDescription('Show TokenSnipe key statistics'),

    // ── NEW COMMANDS ──────────────────────────────────────────────────

    new SlashCommandBuilder()
      .setName('pausekey')
      .setDescription('Pause a key — freezes the timer countdown, user gets kicked within 5 min')
      .addStringOption(o => o.setName('key').setDescription('The key to pause').setRequired(true)),

    new SlashCommandBuilder()
      .setName('resumekey')
      .setDescription('Resume a paused key — timer continues from where it was frozen')
      .addStringOption(o => o.setName('key').setDescription('The key to resume').setRequired(true)),

    new SlashCommandBuilder()
      .setName('activeusers')
      .setDescription('Show all users who have been active in the last N minutes')
      .addIntegerOption(o => o.setName('minutes').setDescription('How many minutes to look back (default 30)').setRequired(false)),

    new SlashCommandBuilder()
      .setName('transferkey')
      .setDescription('Reset HWID and update the note on a key (for transferring to a new user)')
      .addStringOption(o => o.setName('key').setDescription('The key to transfer').setRequired(true))
      .addStringOption(o => o.setName('note').setDescription('New owner note').setRequired(true)),

    new SlashCommandBuilder()
      .setName('addnote')
      .setDescription('Add or update the note on a key')
      .addStringOption(o => o.setName('key').setDescription('The key to update').setRequired(true))
      .addStringOption(o => o.setName('note').setDescription('New note').setRequired(true)),

    new SlashCommandBuilder()
      .setName('whois')
      .setDescription('Find a key by note or HWID')
      .addStringOption(o => o.setName('search').setDescription('Name, note, or HWID to search').setRequired(true)),

    new SlashCommandBuilder()
      .setName('bulkrevoke')
      .setDescription('Revoke all expired keys at once to clean up the list'),

    new SlashCommandBuilder()
      .setName('genkey-opticore')
      .setDescription('Generate a new OptiCore license key')
      .addStringOption(o => o.setName('note').setDescription('Who is this key for?').setRequired(false))
      .addStringOption(o => o.setName('duration').setDescription('How long?').setRequired(false).addChoices(...DURATION_CHOICES)),

  ].map(c => c.toJSON());

  client.once('clientReady', async () => {
    console.log(`Discord bot logged in as ${client.user.tag}`);

    // Set bot status
    client.user.setPresence({
      activities: [{ name: 'TokenSnipe Keys', type: 3 }], // type 3 = Watching
      status: 'online',
    });

    try {
      const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
      await rest.put(Routes.applicationGuildCommands(client.user.id, DISCORD_GUILD), { body: commands });
      console.log('Discord slash commands registered');
    } catch (e) { console.error('Failed to register commands:', e); }
  });

  client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.guildId !== DISCORD_GUILD)
      return interaction.reply({ content: 'This bot only works in the TokenSnipe server.', ephemeral: true });

    const member  = interaction.member;
    const hasRole = member.roles.cache.has(DISCORD_ROLE);
    if (!hasRole)
      return interaction.reply({ content: 'You need the owner role to use this command.', ephemeral: true });

    const { commandName } = interaction;

    // ── /genkey-opticore ─────────────────────────────────────────────────
    if (commandName === 'genkey-opticore') {
      const note     = interaction.options.getString('note') || '';
      const duration = interaction.options.getString('duration') || 'lifetime';
      const key      = 'OC-' + crypto.randomBytes(8).toString('hex').toUpperCase();
      const keys     = loadKeys();
      const { label, isLifetime } = parseDuration(duration);

      keys[key] = {
        active: true, paused: false, pausedTimeLeft: null,
        created: new Date().toISOString(), note,
        duration: label, pendingDuration: isLifetime ? null : duration,
        expiresAt: null, firstActivated: null,
        activations: 0, hwid: null, lastUsed: null,
        createdBy: interaction.user.tag,
        product: 'opticore',
      };
      saveKeys(keys);

      const embed = new EmbedBuilder()
        .setColor(0x9333ea).setTitle('✅ OptiCore Key Generated')
        .addFields(
          { name: 'Key',          value: '```' + key + '```', inline: false },
          { name: 'Duration',     value: label,                inline: true  },
          { name: 'Note',         value: note || 'None',       inline: true  },
          { name: 'Product',      value: 'OptiCore',           inline: true  },
          { name: 'Timer starts', value: isLifetime ? 'N/A — Lifetime' : 'On first login', inline: true },
        )
        .setFooter({ text: 'Generated by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /genkey ──────────────────────────────────────────────────────
    if (commandName === 'genkey') {
      const note     = interaction.options.getString('note') || '';
      const duration = interaction.options.getString('duration') || 'lifetime';
      const key      = 'TS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
      const keys     = loadKeys();
      const { label, isLifetime } = parseDuration(duration);

      keys[key] = {
        active: true, paused: false, pausedTimeLeft: null,
        created: new Date().toISOString(), note,
        duration: label, pendingDuration: isLifetime ? null : duration,
        expiresAt: null, firstActivated: null,
        activations: 0, hwid: null, lastUsed: null,
        createdBy: interaction.user.tag,
      };
      saveKeys(keys);

      const embed = new EmbedBuilder()
        .setColor(0x10b981).setTitle('✅ Key Generated')
        .addFields(
          { name: 'Key',         value: '```' + key + '```', inline: false },
          { name: 'Duration',    value: label,                inline: true  },
          { name: 'Note',        value: note || 'None',       inline: true  },
          { name: 'Timer starts', value: isLifetime ? 'N/A — Lifetime' : 'On first login', inline: true },
        )
        .setFooter({ text: 'Generated by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /revokekey ───────────────────────────────────────────────────
    if (commandName === 'revokekey') {
      const key  = interaction.options.getString('key').toUpperCase();
      const keys = loadKeys();
      if (!keys[key]) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      keys[key].active = false;
      saveKeys(keys);
      const embed = new EmbedBuilder()
        .setColor(0xef4444).setTitle('🔴 Key Revoked')
        .setDescription('`' + key + '` revoked. User will be kicked within 5 minutes.')
        .setFooter({ text: 'Revoked by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /reactivate ──────────────────────────────────────────────────
    if (commandName === 'reactivate') {
      const key  = interaction.options.getString('key').toUpperCase();
      const keys = loadKeys();
      if (!keys[key]) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      keys[key].active = true;
      saveKeys(keys);
      const embed = new EmbedBuilder()
        .setColor(0x10b981).setTitle('✅ Key Reactivated')
        .setDescription('`' + key + '` is now active again.')
        .setFooter({ text: 'Reactivated by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /keyinfo ─────────────────────────────────────────────────────
    if (commandName === 'keyinfo') {
      const key   = interaction.options.getString('key').toUpperCase();
      const keys  = loadKeys();
      const entry = keys[key];
      if (!entry) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });

      const now       = new Date();
      const isPending = !entry.firstActivated && entry.pendingDuration;
      const isPaused  = entry.paused;
      const isExpired = entry.expiresAt && new Date(entry.expiresAt) <= now;
      const status    = !entry.active ? '🔴 Revoked'
                      : isPaused      ? '⏸️ Paused'
                      : isPending     ? '⏳ Not activated yet'
                      : isExpired     ? '💀 Expired'
                      :                 '🟢 Active';
      const color     = !entry.active ? 0xef4444 : isPaused ? 0x6366f1 : isPending ? 0xf59e0b : isExpired ? 0x6b7280 : 0x10b981;

      let expiryField = 'Never (Lifetime)';
      if (isPaused && entry.pausedTimeLeft) {
        const ms   = entry.pausedTimeLeft;
        const d    = Math.floor(ms/86400000), h = Math.floor((ms%86400000)/3600000), m = Math.floor((ms%3600000)/60000);
        expiryField = `⏸️ Paused — **${d}d ${h}h ${m}m** remaining when resumed`;
      } else if (isPending) {
        expiryField = 'Starts on first login\nDuration: ' + entry.duration;
      } else if (entry.expiresAt) {
        const unixTs = Math.floor(new Date(entry.expiresAt).getTime() / 1000);
        expiryField  = '<t:' + unixTs + ':F>\n⏱️ <t:' + unixTs + ':R>';
      }

      const createdUnix = Math.floor(new Date(entry.created).getTime() / 1000);
      let firstActField = 'Never activated';
      if (entry.firstActivated) {
        const u = Math.floor(new Date(entry.firstActivated).getTime() / 1000);
        firstActField = '<t:' + u + ':F>';
      }
      let lastUsedField = 'Never';
      if (entry.lastUsed) {
        const u = Math.floor(new Date(entry.lastUsed).getTime() / 1000);
        lastUsedField = '<t:' + u + ':R>';
      }

      const embed = new EmbedBuilder()
        .setColor(color).setTitle('🔍 Key Info')
        .setDescription('```' + key + '```')
        .addFields(
          { name: 'Status',     value: status,                      inline: true },
          { name: 'HWID',       value: entry.hwid ? '🔒 Locked' : '🔓 Free', inline: true },
          { name: 'Uses',       value: String(entry.activations||0), inline: true },
          { name: 'Note',       value: entry.note||'None',           inline: true },
          { name: 'Duration',   value: entry.duration||'Lifetime',   inline: true },
          { name: 'Created By', value: entry.createdBy||'Dashboard', inline: true },
          { name: 'Expiry / Time Left', value: expiryField,          inline: false },
          { name: 'First Activated',    value: firstActField,         inline: true },
          { name: 'Last Used',          value: lastUsedField,         inline: true },
          { name: 'Created',            value: '<t:' + createdUnix + ':D>', inline: true },
        ).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /resetwid ────────────────────────────────────────────────────
    if (commandName === 'resetwid') {
      const key  = interaction.options.getString('key').toUpperCase();
      const keys = loadKeys();
      if (!keys[key]) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      keys[key].hwid = null; keys[key].lockedAt = null;
      saveKeys(keys);
      const embed = new EmbedBuilder()
        .setColor(0xa78bfa).setTitle('🔓 HWID Reset')
        .setDescription('`' + key + '` can now be used on a new device.')
        .setFooter({ text: 'Reset by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /deletekey ───────────────────────────────────────────────────
    if (commandName === 'deletekey') {
      const key  = interaction.options.getString('key').toUpperCase();
      const keys = loadKeys();
      if (!keys[key]) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      const note = keys[key].note || '';
      delete keys[key];
      saveKeys(keys);
      const embed = new EmbedBuilder()
        .setColor(0xef4444).setTitle('🗑️ Key Deleted')
        .setDescription('`' + key + '`' + (note ? ' (' + note + ')' : '') + ' permanently deleted.')
        .setFooter({ text: 'Deleted by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /extendkey ───────────────────────────────────────────────────
    if (commandName === 'extendkey') {
      const key      = interaction.options.getString('key').toUpperCase();
      const duration = interaction.options.getString('duration');
      const keys     = loadKeys();
      const entry    = keys[key];
      if (!entry) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      const { ms, label } = parseDuration(duration);
      if (ms === 0) return interaction.reply({ content: '❌ Invalid duration.', ephemeral: true });
      const base = (entry.expiresAt && new Date(entry.expiresAt) > new Date()) ? new Date(entry.expiresAt) : new Date();
      entry.expiresAt = new Date(base.getTime() + ms).toISOString();
      entry.duration  = (entry.duration||'') + ' +' + label;
      saveKeys(keys);
      const unixTs = Math.floor(new Date(entry.expiresAt).getTime()/1000);
      const embed = new EmbedBuilder()
        .setColor(0x10b981).setTitle('⏰ Key Extended')
        .addFields(
          { name: 'Key',         value: '`' + key + '`',      inline: false },
          { name: 'Extended by', value: label,                 inline: true  },
          { name: 'New expiry',  value: '<t:'+unixTs+':F>\n⏱️ <t:'+unixTs+':R>', inline: true },
        ).setFooter({ text: 'Extended by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /pausekey ────────────────────────────────────────────────────
    if (commandName === 'pausekey') {
      const key   = interaction.options.getString('key').toUpperCase();
      const keys  = loadKeys();
      const entry = keys[key];
      if (!entry) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      if (!entry.active) return interaction.reply({ content: '❌ Key is already revoked.', ephemeral: true });
      if (entry.paused)  return interaction.reply({ content: '⏸️ Key is already paused.', ephemeral: true });
      if (!entry.expiresAt) return interaction.reply({ content: '❌ Cannot pause a Lifetime key — it has no timer.', ephemeral: true });

      // Freeze the remaining time
      const timeLeft = new Date(entry.expiresAt).getTime() - Date.now();
      if (timeLeft <= 0) return interaction.reply({ content: '❌ Key is already expired.', ephemeral: true });

      entry.paused         = true;
      entry.pausedTimeLeft = timeLeft;
      entry.pausedAt       = new Date().toISOString();
      // Clear expiresAt so heartbeat doesn't kick the user for expiry
      // The key is also marked inactive so heartbeat returns 401 and kicks user
      entry.active = false;
      saveKeys(keys);

      const d = Math.floor(timeLeft/86400000), h = Math.floor((timeLeft%86400000)/3600000), m = Math.floor((timeLeft%3600000)/60000);
      const embed = new EmbedBuilder()
        .setColor(0x6366f1).setTitle('⏸️ Key Paused')
        .setDescription('`' + key + '`' + (entry.note ? ' (' + entry.note + ')' : ''))
        .addFields(
          { name: 'Time frozen',  value: `**${d}d ${h}h ${m}m** remaining`, inline: true },
          { name: 'User status',  value: 'Will be kicked within 5 minutes',  inline: true },
          { name: 'To resume',    value: 'Use `/resumekey ' + key + '`',      inline: false },
        )
        .setFooter({ text: 'Paused by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /resumekey ───────────────────────────────────────────────────
    if (commandName === 'resumekey') {
      const key   = interaction.options.getString('key').toUpperCase();
      const keys  = loadKeys();
      const entry = keys[key];
      if (!entry) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      if (!entry.paused) return interaction.reply({ content: '❌ Key is not paused.', ephemeral: true });

      // Restore timer from frozen time left
      const newExpiry  = new Date(Date.now() + entry.pausedTimeLeft);
      entry.expiresAt  = newExpiry.toISOString();
      entry.active     = true;
      entry.paused     = false;
      entry.pausedTimeLeft = null;
      entry.pausedAt   = null;
      saveKeys(keys);

      const unixTs = Math.floor(newExpiry.getTime()/1000);
      const embed = new EmbedBuilder()
        .setColor(0x10b981).setTitle('▶️ Key Resumed')
        .setDescription('`' + key + '`' + (entry.note ? ' (' + entry.note + ')' : ''))
        .addFields(
          { name: 'New expiry', value: '<t:'+unixTs+':F>\n⏱️ <t:'+unixTs+':R>', inline: false },
        )
        .setFooter({ text: 'Resumed by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /activeusers ─────────────────────────────────────────────────
    if (commandName === 'activeusers') {
      const minutes = interaction.options.getInteger('minutes') || 30;
      const keys    = loadKeys();
      const cutoff  = new Date(Date.now() - minutes * 60 * 1000);
      const active  = Object.entries(keys).filter(([, v]) =>
        v.lastUsed && new Date(v.lastUsed) >= cutoff && v.active
      ).sort((a, b) => new Date(b[1].lastUsed) - new Date(a[1].lastUsed));

      if (!active.length) {
        return interaction.reply({ content: `😴 No users active in the last **${minutes} minutes**.`, ephemeral: true });
      }

      const lines = active.slice(0, 20).map(([k, v]) => {
        const unixUsed = Math.floor(new Date(v.lastUsed).getTime() / 1000);
        const isPaused = v.paused ? ' ⏸️' : '';
        return `🟢${isPaused} \`${k}\` — ${v.note || 'no note'} — last seen <t:${unixUsed}:R>`;
      });

      const embed = new EmbedBuilder()
        .setColor(0x10b981)
        .setTitle(`👥 Active Users — Last ${minutes} Minutes (${active.length})`)
        .setDescription(lines.join('\n') + (active.length > 20 ? `\n...and ${active.length - 20} more` : ''))
        .setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /transferkey ─────────────────────────────────────────────────
    if (commandName === 'transferkey') {
      const key   = interaction.options.getString('key').toUpperCase();
      const note  = interaction.options.getString('note');
      const keys  = loadKeys();
      const entry = keys[key];
      if (!entry) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });

      const oldNote  = entry.note;
      entry.hwid     = null;
      entry.lockedAt = null;
      entry.note     = note;
      entry.active   = true;
      saveKeys(keys);

      const embed = new EmbedBuilder()
        .setColor(0x60a5fa).setTitle('🔄 Key Transferred')
        .setDescription('`' + key + '`')
        .addFields(
          { name: 'Old owner', value: oldNote || 'None', inline: true },
          { name: 'New owner', value: note,               inline: true },
          { name: 'HWID',      value: '🔓 Reset — ready for new device', inline: false },
        )
        .setFooter({ text: 'Transferred by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /addnote ─────────────────────────────────────────────────────
    if (commandName === 'addnote') {
      const key   = interaction.options.getString('key').toUpperCase();
      const note  = interaction.options.getString('note');
      const keys  = loadKeys();
      if (!keys[key]) return interaction.reply({ content: '❌ Key not found: `' + key + '`', ephemeral: true });
      const oldNote  = keys[key].note;
      keys[key].note = note;
      saveKeys(keys);
      const embed = new EmbedBuilder()
        .setColor(0xf59e0b).setTitle('📝 Note Updated')
        .addFields(
          { name: 'Key',      value: '`' + key + '`', inline: false },
          { name: 'Old note', value: oldNote || 'None', inline: true },
          { name: 'New note', value: note,               inline: true },
        )
        .setFooter({ text: 'Updated by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /whois ───────────────────────────────────────────────────────
    if (commandName === 'whois') {
      const search = interaction.options.getString('search').toLowerCase();
      const keys   = loadKeys();
      const now    = new Date();
      const matches = Object.entries(keys).filter(([k, v]) =>
        k.toLowerCase().includes(search) ||
        (v.note||'').toLowerCase().includes(search) ||
        (v.hwid||'').toLowerCase().includes(search)
      );

      if (!matches.length) return interaction.reply({ content: `❌ No keys found matching \`${search}\``, ephemeral: true });

      const lines = matches.slice(0, 10).map(([k, v]) => {
        const isPending = !v.firstActivated && v.pendingDuration;
        const isPaused  = v.paused;
        const isExpired = v.expiresAt && new Date(v.expiresAt) <= now;
        const status    = !v.active && !isPaused ? '🔴' : isPaused ? '⏸️' : isPending ? '⏳' : isExpired ? '💀' : '🟢';
        const exp = isPaused ? '⏸️ paused'
                  : isPending ? '⏳ not activated'
                  : v.expiresAt ? '<t:'+Math.floor(new Date(v.expiresAt).getTime()/1000)+':R>'
                  : '∞ lifetime';
        const hwid = v.hwid ? '🔒' : '🔓';
        return `${status} ${hwid} \`${k}\`\n┗ **${v.note||'no note'}** · ${exp}`;
      });

      const embed = new EmbedBuilder()
        .setColor(0xa78bfa).setTitle(`🔎 Who Is "${search}" (${matches.length} result${matches.length!==1?'s':''})`)
        .setDescription(lines.join('\n\n') + (matches.length > 10 ? `\n\n...and ${matches.length - 10} more` : ''))
        .setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /bulkrevoke ──────────────────────────────────────────────────
    if (commandName === 'bulkrevoke') {
      const keys  = loadKeys();
      const now   = new Date();
      let count   = 0;
      for (const [, v] of Object.entries(keys)) {
        if (v.active && v.expiresAt && new Date(v.expiresAt) <= now) {
          v.active = false;
          count++;
        }
      }
      saveKeys(keys);
      const embed = new EmbedBuilder()
        .setColor(count > 0 ? 0xef4444 : 0x6b7280)
        .setTitle('🧹 Bulk Revoke Complete')
        .setDescription(count > 0
          ? `Revoked **${count}** expired key${count !== 1 ? 's' : ''}.`
          : 'No expired keys found — list is already clean.')
        .setFooter({ text: 'Run by ' + interaction.user.tag }).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /listkeys ────────────────────────────────────────────────────
    if (commandName === 'listkeys') {
      const filter = interaction.options.getString('filter') || 'all';
      const keys   = loadKeys();
      const now    = new Date();
      let entries  = Object.entries(keys);
      // 'active' includes both activated keys AND pending (not yet activated) keys
      if (filter === 'active')  entries = entries.filter(([,v]) => v.active && !v.paused && (!v.expiresAt || new Date(v.expiresAt) > now));
      if (filter === 'revoked') entries = entries.filter(([,v]) => !v.active && !v.paused);
      if (filter === 'expired') entries = entries.filter(([,v]) => v.active && v.expiresAt && new Date(v.expiresAt) <= now);
      if (filter === 'pending') entries = entries.filter(([,v]) => v.active && !v.firstActivated && v.pendingDuration);
      if (filter === 'paused')  entries = entries.filter(([,v]) => v.paused);
      // 'all' shows everything — no filter applied

      if (!entries.length) return interaction.reply({ content: `No ${filter} keys found.`, ephemeral: true });

      const lines = entries.slice(0, 20).map(([k, v]) => {
        const isPending = !v.firstActivated && v.pendingDuration;
        const exp = v.paused ? '⏸️ paused'
                  : isPending ? '⏳ not activated'
                  : v.expiresAt ? '<t:'+Math.floor(new Date(v.expiresAt).getTime()/1000)+':R>'
                  : '∞ lifetime';
        const lu = v.lastUsed ? '<t:'+Math.floor(new Date(v.lastUsed).getTime()/1000)+':R>' : 'never';
        return `\`${k}\` — ${v.note||'no note'} — ${exp} — last: ${lu}`;
      });

      const embed = new EmbedBuilder()
        .setColor(0x3b82f6)
        .setTitle(`${filter.charAt(0).toUpperCase()+filter.slice(1)} Keys (${entries.length})`)
        .setDescription(lines.join('\n') + (entries.length > 20 ? `\n...and ${entries.length-20} more` : ''))
        .setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /listnotes ───────────────────────────────────────────────────
    if (commandName === 'listnotes') {
      const query   = (interaction.options.getString('search') || '').toLowerCase();
      const keys    = loadKeys();
      const now     = new Date();
      const matches = Object.entries(keys).filter(([k, v]) =>
        !query || (v.note||'').toLowerCase().includes(query) || k.toLowerCase().includes(query)
      );
      if (!matches.length) return interaction.reply({ content: 'No keys found.', ephemeral: true });
      const lines = matches.slice(0, 25).map(([k, v]) => {
        const isPending = !v.firstActivated && v.pendingDuration;
        const status    = !v.active ? '🔴' : v.paused ? '⏸️' : isPending ? '⏳' : (v.expiresAt && new Date(v.expiresAt) <= now) ? '💀' : '🟢';
        const exp = v.paused ? 'paused' : isPending ? 'not activated' : v.expiresAt ? '<t:'+Math.floor(new Date(v.expiresAt).getTime()/1000)+':R>' : 'lifetime';
        return `${status} \`${k}\` — ${v.note||'no note'} — ${exp}`;
      });
      const embed = new EmbedBuilder()
        .setColor(0x3b82f6)
        .setTitle('Keys' + (query ? ` matching "${query}"` : '') + ` (${matches.length})`)
        .setDescription(lines.join('\n') + (matches.length > 25 ? `\n...and ${matches.length-25} more` : ''))
        .setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }

    // ── /stats ───────────────────────────────────────────────────────
    if (commandName === 'stats') {
      const keys  = loadKeys();
      const vals  = Object.values(keys);
      const now   = new Date();
      const cutoff30 = new Date(Date.now() - 30 * 60 * 1000);
      const total    = vals.length;
      const active   = vals.filter(v => v.active && !v.paused && (!v.expiresAt || new Date(v.expiresAt) > now) && v.firstActivated).length;
      const pending  = vals.filter(v => v.active && !v.firstActivated && v.pendingDuration).length;
      const paused   = vals.filter(v => v.paused).length;
      const revoked  = vals.filter(v => !v.active && !v.paused).length;
      const expired  = vals.filter(v => v.active && v.expiresAt && new Date(v.expiresAt) <= now).length;
      const lifetime = vals.filter(v => v.active && !v.expiresAt && !v.pendingDuration && !v.paused).length;
      const online   = vals.filter(v => v.lastUsed && new Date(v.lastUsed) >= cutoff30 && v.active).length;
      const totalUses = vals.reduce((a, v) => a + (v.activations||0), 0);

      const embed = new EmbedBuilder()
        .setColor(0x3b82f6).setTitle('📊 TokenSnipe Stats')
        .addFields(
          { name: '🟢 Active',      value: String(active),    inline: true },
          { name: '👥 Online (30m)', value: String(online),    inline: true },
          { name: '⏸️ Paused',      value: String(paused),    inline: true },
          { name: '⏳ Pending',      value: String(pending),   inline: true },
          { name: '🔴 Revoked',      value: String(revoked),   inline: true },
          { name: '💀 Expired',      value: String(expired),   inline: true },
          { name: '∞ Lifetime',      value: String(lifetime),  inline: true },
          { name: '📦 Total Keys',   value: String(total),     inline: true },
          { name: '🔑 Total Logins', value: String(totalUses), inline: true },
        ).setTimestamp();
      return interaction.reply({ embeds: [embed], ephemeral: true });
    }
  });

  client.login(DISCORD_TOKEN).catch(e => console.error('Discord login failed:', e));

} else {
  console.log('Discord bot disabled — set DISCORD_TOKEN, DISCORD_GUILD, DISCORD_ROLE to enable');
}

// ── DATABASE — MongoDB (persists across Railway deploys) ──────────────────
// Keys and users are stored in MongoDB so they never get wiped on redeploy.
// loadKeys/saveKeys/loadUsers/saveUsers work synchronously in memory —
// MongoDB is written to async in the background on every save.

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) { console.error('FATAL: MONGODB_URI not set'); process.exit(1); }

const mongoClient = new MongoClient(MONGODB_URI);
let db, keysCol, usersCol;

// In-memory cache — loaded from MongoDB on startup
let _keysCache  = {};
let _usersCache = {};

async function connectDB() {
  await mongoClient.connect();
  db       = mongoClient.db('tokensnipe');
  keysCol  = db.collection('keys');
  usersCol = db.collection('users');

  // Load everything into memory on startup
  const keysDoc  = await keysCol.findOne({ _id: 'keys' });
  const usersDoc = await usersCol.findOne({ _id: 'users' });
  _keysCache  = keysDoc  ? keysDoc.data  : {};
  _usersCache = usersDoc ? usersDoc.data : {};

  console.log(`MongoDB connected — ${Object.keys(_keysCache).length} keys, ${Object.keys(_usersCache).length} users loaded`);
}

// Synchronous in-memory reads (fast, no await needed)
function loadKeys()  { return _keysCache; }
function loadUsers() { return _usersCache; }

// Sync update + async MongoDB write
function saveKeys(k) {
  _keysCache = k;
  keysCol.replaceOne({ _id: 'keys' }, { _id: 'keys', data: k }, { upsert: true })
    .catch(e => console.error('MongoDB saveKeys error:', e));
}
function saveUsers(u) {
  _usersCache = u;
  usersCol.replaceOne({ _id: 'users' }, { _id: 'users', data: u }, { upsert: true })
    .catch(e => console.error('MongoDB saveUsers error:', e));
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-et-token, x-hwid, x-admin-key, x-panel-token, x-app-version');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const rlMap = new Map();
function rateLimit(key, max) {
  const now = Date.now();
  const e   = rlMap.get(key) || { count: 0, reset: now + 60000 };
  if (now > e.reset) { e.count = 0; e.reset = now + 60000; }
  e.count++; rlMap.set(key, e);
  return e.count > max;
}

// ── AUTH HELPERS ──────────────────────────────────────────────────────────
function isSuperAdmin(req) { return (req.headers['x-admin-key'] || req.query.ak) === ADMIN_KEY; }
function requireSuperAdmin(req, res, next) { if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Superadmin only' }); next(); }
function requirePanel(req, res, next) {
  if (isSuperAdmin(req)) { req.isSuperAdmin = true; return next(); }
  const tok = req.headers['x-panel-token'];
  if (!tok) return res.status(403).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(tok, JWT_SECRET + '_panel');
    const users   = loadUsers();
    if (!users[payload.username] || !users[payload.username].active)
      return res.status(403).json({ error: 'Panel account revoked' });
    req.panelUser = payload.username; req.isSuperAdmin = false; next();
  } catch { return res.status(403).json({ error: 'Invalid panel token' }); }
}
function requireToken(req, res, next) {
  const token = req.headers['x-et-token'];
  const hwid  = req.headers['x-hwid'];
  if (!token) return res.status(401).json({ error: 'No token' });

  // Version check — reject old builds on heartbeat too
  const clientVersion = parseInt(req.headers['x-app-version'] || '0');
  if (clientVersion < MIN_VERSION)
    return res.status(426).json({ error: 'UPDATE_REQUIRED' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const keys    = loadKeys();
    const entry   = keys[payload.key];
    if (!entry || !entry.active) return res.status(401).json({ error: 'Key revoked' });
    if (entry.expiresAt && new Date() > new Date(entry.expiresAt)) return res.status(401).json({ error: 'Key expired' });
    if (entry.hwid && entry.hwid !== hwid) return res.status(401).json({ error: 'HWID mismatch' });
    req.keyPayload = payload; next();
  } catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ── DURATION PARSER ───────────────────────────────────────────────────────
function parseDuration(duration) {
  if (!duration || duration === 'lifetime') return { ms: 0, label: 'Lifetime', isLifetime: true };
  const type = duration[0], num = parseInt(duration.slice(1));
  let ms = 0, label = '';
  if (type === 'h' && !isNaN(num)) { ms = num * 3600000;          label = num + ' hour'  + (num>1?'s':''); }
  else if (type === 'd' && !isNaN(num)) { ms = num * 86400000;    label = num + ' day'   + (num>1?'s':''); }
  else if (type === 'm' && !isNaN(num)) { ms = num * 30*86400000; label = num + ' month' + (num>1?'s':''); }
  else if (!isNaN(parseInt(duration))) { ms = parseInt(duration)*86400000; label = duration + ' days'; }
  return { ms, label, isLifetime: false };
}

// ── EXTENSION ROUTES ──────────────────────────────────────────────────────
// ── VERSION CHECK — called on app launch before key gate ─────────────────
app.get('/version-check', (req, res) => {
  const clientVersion = parseInt(req.headers['x-app-version'] || '0');
  if (clientVersion < MIN_VERSION)
    return res.status(426).json({ error: 'UPDATE_REQUIRED', minVersion: MIN_VERSION });
  res.json({ ok: true, version: clientVersion });
});

app.post('/validate', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ valid: false, error: 'Missing fields' });

  // Version check — reject old builds
  const clientVersion = parseInt(req.headers['x-app-version'] || '0');
  if (clientVersion < MIN_VERSION)
    return res.json({ valid: false, error: 'UPDATE_REQUIRED' });

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (rateLimit(ip, 5)) return res.status(429).json({ valid: false, error: 'Too many attempts. Wait a minute.' });
  const keys   = loadKeys();
  const entry  = keys[key];
  if (!entry || !entry.active) return res.json({ valid: false, error: 'Invalid or revoked key' });
  if (entry.paused) return res.json({ valid: false, error: 'This key is currently paused. Contact support.' });

  // Product check — OptiCore keys start with OC-, TokenSnipe keys start with TS-
  // Keys without a prefix work for both (backwards compatible)
  const product = req.body.product || 'tokensnipe';
  if (product === 'opticore' && key.startsWith('TS-'))
    return res.json({ valid: false, error: 'This is a TokenSnipe key. Use an OptiCore key.' });
  if (product === 'tokensnipe' && key.startsWith('OC-'))
    return res.json({ valid: false, error: 'This is an OptiCore key. Use a TokenSnipe key.' });

  if (!entry.firstActivated && entry.pendingDuration) {
    const dur = entry.pendingDuration;
    const { ms } = parseDuration(dur);
    if (ms > 0) entry.expiresAt = new Date(Date.now() + ms).toISOString();
    entry.firstActivated = new Date().toISOString();
    delete entry.pendingDuration;
  }

  if (entry.expiresAt && new Date() > new Date(entry.expiresAt))
    return res.json({ valid: false, error: 'Key has expired' });

  if (!entry.hwid) { entry.hwid = hwid; entry.lockedAt = new Date().toISOString(); }
  else if (entry.hwid !== hwid) return res.json({ valid: false, error: 'Key is locked to another device' });

  entry.lastUsed    = new Date().toISOString();
  entry.activations = (entry.activations || 0) + 1;
  saveKeys(keys);
  const token = jwt.sign({ key, hwid }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ valid: true, token, expiresAt: entry.expiresAt || null, note: entry.note || '' });
});

app.get('/heartbeat', requireToken, (req, res) => {
  const keys  = loadKeys();
  const entry = keys[req.keyPayload.key];
  res.json({ ok: true, expiresAt: entry?.expiresAt || null, note: entry?.note || '' });
});

// ── PANEL LOGIN ───────────────────────────────────────────────────────────
app.post('/panel/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (rateLimit('panel:' + ip, 5)) return res.status(429).json({ error: 'Too many attempts' });
  const users = loadUsers();
  const user  = users[username];
  if (!user || !user.active) return res.status(403).json({ error: 'Invalid credentials' });
  const hash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex');
  if (hash !== user.passwordHash) return res.status(403).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ username }, JWT_SECRET + '_panel', { expiresIn: '24h' });
  res.json({ ok: true, token, username });
});

// ── ADMIN API ─────────────────────────────────────────────────────────────
app.get('/admin/keys', requirePanel, (req, res) => res.json(loadKeys()));
app.post('/admin/keys/revoke',      requirePanel, (req, res) => { const { key } = req.body; const keys = loadKeys(); if (!keys[key]) return res.status(404).json({ error: 'Not found' }); keys[key].active = false; saveKeys(keys); res.json({ ok: true }); });
app.post('/admin/keys/reactivate',  requirePanel, (req, res) => { const { key } = req.body; const keys = loadKeys(); if (!keys[key]) return res.status(404).json({ error: 'Not found' }); keys[key].active = true; saveKeys(keys); res.json({ ok: true }); });
app.post('/admin/keys/reset-hwid',  requirePanel, (req, res) => { const { key } = req.body; const keys = loadKeys(); if (!keys[key]) return res.status(404).json({ error: 'Not found' }); keys[key].hwid = null; keys[key].lockedAt = null; saveKeys(keys); res.json({ ok: true }); });
app.post('/admin/keys/delete',      requirePanel, (req, res) => { const { key } = req.body; const keys = loadKeys(); if (!keys[key]) return res.status(404).json({ error: 'Not found' }); delete keys[key]; saveKeys(keys); res.json({ ok: true }); });
app.post('/admin/keys/create', requirePanel, (req, res) => {
  const { note, duration } = req.body;
  const key  = 'TS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
  const keys = loadKeys();
  const { ms, label, isLifetime } = parseDuration(duration);
  keys[key] = {
    active: true, paused: false, pausedTimeLeft: null,
    created: new Date().toISOString(), note: note || '', duration: label,
    pendingDuration: isLifetime ? null : duration, expiresAt: null,
    firstActivated: null, activations: 0, hwid: null, lastUsed: null,
  };
  saveKeys(keys);
  res.json({ key, duration: label, startsOnLogin: !isLifetime });
});

app.get('/admin/users',              requireSuperAdmin, (req, res) => { const users = loadUsers(); const safe = {}; Object.entries(users).forEach(([u,v]) => { safe[u] = { active: v.active, created: v.created, note: v.note }; }); res.json(safe); });
app.post('/admin/users/create',      requireSuperAdmin, (req, res) => { const { username, password, note } = req.body; if (!username||!password) return res.status(400).json({ error: 'Missing fields' }); const users = loadUsers(); if (users[username]) return res.status(400).json({ error: 'Username exists' }); const hash = crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex'); users[username] = { active: true, created: new Date().toISOString(), note: note||'', passwordHash: hash }; saveUsers(users); res.json({ ok: true }); });
app.post('/admin/users/revoke',      requireSuperAdmin, (req, res) => { const { username } = req.body; const users = loadUsers(); if (!users[username]) return res.status(404).json({ error: 'Not found' }); users[username].active = false; saveUsers(users); res.json({ ok: true }); });
app.post('/admin/users/delete',      requireSuperAdmin, (req, res) => { const { username } = req.body; const users = loadUsers(); if (!users[username]) return res.status(404).json({ error: 'Not found' }); delete users[username]; saveUsers(users); res.json({ ok: true }); });

// ── ADMIN DASHBOARD ───────────────────────────────────────────────────────
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:;");
  // Serve the full dashboard HTML (unchanged from v3 — keeping it identical so dashboard still works)
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TokenSnipe Admin</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#07090f;--surf:#0e1420;--card:#131c2e;--border:rgba(59,130,246,0.15);--bhi:rgba(59,130,246,0.3);--blue:#3b82f6;--blt:#60a5fa;--t1:#f1f5f9;--t2:#94a3b8;--t3:#475569;--green:#10b981;--red:#ef4444;--gold:#f59e0b;--purple:#a78bfa}
body{background:var(--bg);color:var(--t1);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}
#login{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.login-box{background:var(--surf);border:1px solid var(--border);border-radius:16px;padding:36px;width:100%;max-width:380px;display:flex;flex-direction:column;gap:14px;text-align:center}
.login-box h1{font-size:20px;font-weight:700}
.login-tabs{display:flex;gap:6px;margin-bottom:2px}
.ltab{flex:1;padding:7px;border-radius:8px;font-size:12px;font-weight:600;font-family:inherit;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--t3);transition:all .15s}
.ltab.on{background:rgba(59,130,246,.12);border-color:var(--bhi);color:var(--blt)}
input,select{width:100%;padding:9px 13px;background:var(--card);border:1px solid var(--border);border-radius:8px;color:var(--t1);font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
input:focus{border-color:var(--bhi)}select option{background:var(--card)}
#app{display:none;flex-direction:column;min-height:100vh}
.topbar{background:var(--surf);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
.topbar h1{font-size:15px;font-weight:700}
.role-badge{font-size:10px;padding:2px 8px;border-radius:20px;font-weight:700}
.role-badge.super{background:rgba(234,179,8,.12);border:1px solid rgba(234,179,8,.3);color:var(--gold)}
.role-badge.panel{background:rgba(59,130,246,.1);border:1px solid var(--border);color:var(--blt)}
.main{padding:20px 24px;display:flex;flex-direction:column;gap:16px;max-width:1200px;margin:0 auto;width:100%}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.stat{background:var(--surf);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.stat-val{font-size:26px;font-weight:700;margin-bottom:2px}.stat-label{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.06em}
.card{background:var(--surf);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.card-header{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.card-header h2{font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.08em}
.card-body{padding:16px}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.field{display:flex;flex-direction:column;gap:4px}.field label{font-size:10px;color:var(--t3);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.field input,.field select{min-width:150px}
.search{padding:6px 12px;background:var(--card);border:1px solid var(--border);border-radius:7px;color:var(--t1);font-size:12px;font-family:inherit;outline:none;width:220px}
table{width:100%;border-collapse:collapse}
th{padding:8px 12px;text-align:left;font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid rgba(59,130,246,0.05);font-size:12px;vertical-align:middle}
tr:last-child td{border-bottom:none}tr:hover td{background:rgba(59,130,246,0.03)}
.key-mono{font-family:monospace;font-size:12px;color:var(--blt);font-weight:600;cursor:pointer}.key-mono:hover{color:#93c5fd}
.badge{display:inline-flex;align-items:center;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;white-space:nowrap}
.badge.active{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.25);color:var(--green)}
.badge.revoked{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);color:var(--red)}
.badge.expired{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.25);color:var(--gold)}
.badge.paused{background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);color:#818cf8}
.badge.locked{background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.25);color:var(--purple)}
.badge.free{background:rgba(100,116,139,.1);border:1px solid rgba(100,116,139,.2);color:var(--t3)}
.actions{display:flex;gap:4px;flex-wrap:wrap}
button{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;font-family:inherit;cursor:pointer;border:1px solid;transition:all .15s;white-space:nowrap}
.btn-primary{padding:9px 20px;background:linear-gradient(135deg,#1e40af,#3b82f6);border-color:var(--bhi);color:#fff;font-size:12px;border-radius:8px}.btn-primary:hover{opacity:.9}
.btn-revoke{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.3);color:#f87171}.btn-revoke:hover{background:rgba(239,68,68,.2)}
.btn-activate{background:rgba(16,185,129,.08);border-color:rgba(16,185,129,.3);color:var(--green)}.btn-activate:hover{background:rgba(16,185,129,.2)}
.btn-hwid{background:rgba(167,139,250,.08);border-color:rgba(167,139,250,.3);color:var(--purple)}.btn-hwid:hover{background:rgba(167,139,250,.2)}
.btn-delete{background:rgba(239,68,68,.04);border-color:rgba(100,116,139,.2);color:var(--t3)}.btn-delete:hover{background:rgba(239,68,68,.15);color:#f87171}
.btn-logout{background:transparent;border-color:var(--border);color:var(--t3)}.btn-logout:hover{border-color:rgba(239,68,68,.3);color:#f87171}
.btn-pause{background:rgba(99,102,241,.08);border-color:rgba(99,102,241,.3);color:#818cf8}.btn-pause:hover{background:rgba(99,102,241,.2)}
.ftab{background:transparent;border:1px solid var(--border);color:var(--t3);border-radius:20px;padding:3px 12px;font-size:11px}.ftab.on{background:rgba(59,130,246,.1);border-color:var(--bhi);color:var(--blt)}
.note-col{color:var(--t2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.expiry-ok{color:var(--green)}.expiry-soon{color:var(--gold)}.expiry-exp{color:var(--red)}.expiry-never{color:var(--t3)}
.new-key-box{margin-top:12px;padding:10px 14px;background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.2);border-radius:8px;display:none}
.new-key-box p{font-size:10px;color:var(--t3);margin-bottom:4px}.new-key-val{font-family:monospace;font-size:15px;color:var(--green);font-weight:700;cursor:pointer}
.superonly{display:none}
.toast{position:fixed;bottom:20px;right:20px;padding:10px 18px;background:var(--card);border:1px solid var(--border);border-radius:10px;font-size:12px;font-weight:600;z-index:100;animation:tin .2s ease;pointer-events:none}
.toast.ok{border-color:rgba(16,185,129,.4);color:var(--green)}.toast.err{border-color:rgba(239,68,68,.4);color:var(--red)}
@keyframes tin{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.empty-row td{text-align:center;padding:32px;color:var(--t3)}
</style>
</head>
<body>
<div id="login">
  <div class="login-box">
    <div><div style="font-size:32px;margin-bottom:8px">🎯</div><h1>TokenSnipe Admin</h1><p style="color:var(--t3);font-size:12px;margin-top:4px">Sign in to manage keys</p></div>
    <div class="login-tabs">
      <button class="ltab on" id="tab-admin" onclick="switchLoginTab('admin')">Superadmin</button>
      <button class="ltab" id="tab-panel" onclick="switchLoginTab('panel')">Panel User</button>
    </div>
    <div id="login-admin"><input id="ak" type="password" placeholder="Admin key..." /></div>
    <div id="login-panel" style="display:none;flex-direction:column;gap:8px">
      <input id="pu-user" type="text" placeholder="Username" autocomplete="off" />
      <input id="pu-pass" type="password" placeholder="Password" />
    </div>
    <button class="btn-primary" onclick="doLogin()">Login</button>
    <div id="lerr" style="color:var(--red);font-size:11px;min-height:14px"></div>
  </div>
</div>
<div id="app">
  <div class="topbar">
    <div style="display:flex;align-items:center;gap:10px"><h1>TokenSnipe</h1><span class="role-badge super" id="role-badge">Superadmin</span></div>
    <div style="display:flex;align-items:center;gap:8px"><span id="whoami" style="font-size:11px;color:var(--t3)"></span><button class="btn-logout" onclick="logout()">Logout</button></div>
  </div>
  <div class="main">
    <div class="stats">
      <div class="stat"><div class="stat-val" id="s-total" style="color:var(--blt)">0</div><div class="stat-label">Total Keys</div></div>
      <div class="stat"><div class="stat-val" id="s-active" style="color:var(--green)">0</div><div class="stat-label">Active</div></div>
      <div class="stat"><div class="stat-val" id="s-online" style="color:var(--green)">0</div><div class="stat-label">Online (30m)</div></div>
      <div class="stat"><div class="stat-val" id="s-paused" style="color:#818cf8">0</div><div class="stat-label">Paused</div></div>
      <div class="stat"><div class="stat-val" id="s-revoked" style="color:var(--red)">0</div><div class="stat-label">Revoked</div></div>
      <div class="stat"><div class="stat-val" id="s-expired" style="color:var(--gold)">0</div><div class="stat-label">Expired</div></div>
      <div class="stat"><div class="stat-val" id="s-uses" style="color:var(--purple)">0</div><div class="stat-label">Total Logins</div></div>
    </div>
    <div class="card" id="create-key-card">
      <div class="card-header"><h2>Generate New Key</h2></div>
      <div class="card-body">
        <div class="row">
          <div class="field"><label>Note / Username</label><input id="c-note" type="text" placeholder="e.g. Discord user xyz" /></div>
          <div class="field"><label>Duration</label>
            <select id="c-days">
              <optgroup label="Hours"><option value="h1">1 hour</option><option value="h2">2 hours</option><option value="h3">3 hours</option><option value="h6">6 hours</option><option value="h12">12 hours</option><option value="h18">18 hours</option><option value="h23">23 hours</option></optgroup>
              <optgroup label="Days"><option value="d1">1 day</option><option value="d3">3 days</option><option value="d7">7 days</option><option value="d14">14 days</option><option value="d30">30 days</option></optgroup>
              <optgroup label="Months"><option value="m1">1 month</option><option value="m2">2 months</option><option value="m3">3 months</option><option value="m6">6 months</option><option value="m12">12 months</option></optgroup>
              <optgroup label="Permanent"><option value="lifetime" selected>Lifetime</option></optgroup>
            </select>
          </div>
          <button class="btn-primary" onclick="createKey()">+ Generate Key</button>
        </div>
        <div class="new-key-box" id="new-key-box"><p>New key — click to copy:</p><div class="new-key-val" id="new-key-val"></div></div>
      </div>
    </div>
    <div class="card superonly" id="users-card">
      <div class="card-header"><h2>Panel Users</h2></div>
      <div class="card-body">
        <div class="row" style="margin-bottom:12px">
          <div class="field"><label>Username</label><input id="u-name" type="text" placeholder="username" autocomplete="off" /></div>
          <div class="field"><label>Password</label><input id="u-pass" type="text" placeholder="password" /></div>
          <div class="field"><label>Note</label><input id="u-note" type="text" placeholder="optional note" /></div>
          <button class="btn-primary" onclick="createUser()">+ Add User</button>
        </div>
        <div style="overflow-x:auto"><table><thead><tr><th>Username</th><th>Note</th><th>Status</th><th>Actions</th></tr></thead><tbody id="users-body"></tbody></table></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header">
        <h2>All Keys</h2>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <div style="display:flex;gap:4px">
            <button class="ftab on" onclick="setFilter('all',this)">All</button>
            <button class="ftab" onclick="setFilter('active',this)">Active</button>
            <button class="ftab" onclick="setFilter('paused',this)">Paused</button>
            <button class="ftab" onclick="setFilter('revoked',this)">Revoked</button>
            <button class="ftab" onclick="setFilter('expired',this)">Expired</button>
          </div>
          <input class="search" type="text" id="search" placeholder="Search key or note..." oninput="renderTable()" />
        </div>
      </div>
      <div style="overflow-x:auto">
        <table><thead><tr><th>Key</th><th>Note</th><th>Status</th><th>HWID</th><th>Expires</th><th>Uses</th><th>Last Used</th><th>Actions</th></tr></thead><tbody id="keys-body"></tbody></table>
      </div>
    </div>
  </div>
</div>
<script>
let adminKey='',panelToken='',isSuperAdmin=false,whoami='';
let keysData={},usersData={},filterMode='all',loginTab='admin';

function switchLoginTab(tab){
  loginTab=tab;
  document.getElementById('tab-admin').classList.toggle('on',tab==='admin');
  document.getElementById('tab-panel').classList.toggle('on',tab==='panel');
  document.getElementById('login-admin').style.display=tab==='admin'?'block':'none';
  document.getElementById('login-panel').style.display=tab==='panel'?'flex':'none';
}
switchLoginTab('admin');

async function doLogin(){
  document.getElementById('lerr').textContent='';
  if(loginTab==='admin'){
    adminKey=document.getElementById('ak').value.trim();
    if(!adminKey)return;
    const ok=await fetchKeys(true);
    if(ok){isSuperAdmin=true;whoami='Superadmin';showApp();}
    else{document.getElementById('lerr').textContent='Invalid admin key.';adminKey='';}
  }else{
    const user=document.getElementById('pu-user').value.trim(),pass=document.getElementById('pu-pass').value.trim();
    if(!user||!pass)return;
    try{
      const res=await fetch('/panel/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
      const data=await res.json();
      if(data.ok){panelToken=data.token;isSuperAdmin=false;whoami=user;const ok=await fetchKeys(false);if(ok)showApp();}
      else document.getElementById('lerr').textContent=data.error||'Invalid credentials.';
    }catch{document.getElementById('lerr').textContent='Connection error.';}
  }
}
document.addEventListener('keydown',e=>{if(e.key==='Enter'&&document.getElementById('login').style.display!=='none')doLogin();});

function showApp(){
  document.getElementById('login').style.display='none';
  document.getElementById('app').style.display='flex';
  document.getElementById('whoami').textContent=whoami;
  const badge=document.getElementById('role-badge');
  if(isSuperAdmin){badge.textContent='Superadmin';badge.className='role-badge super';}
  else{badge.textContent='Panel User';badge.className='role-badge panel';}
  document.querySelectorAll('.superonly').forEach(el=>{el.style.display=isSuperAdmin?'block':'none';});
  if(isSuperAdmin)fetchUsers();
}

function logout(){
  adminKey='';panelToken='';isSuperAdmin=false;whoami='';keysData={};usersData={};
  document.getElementById('login').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('ak').value='';
  document.getElementById('pu-user').value='';
  document.getElementById('pu-pass').value='';
}

function getHeaders(){const h={'Content-Type':'application/json'};if(isSuperAdmin)h['x-admin-key']=adminKey;else h['x-panel-token']=panelToken;return h;}
async function api(path,method='GET',body=null){const opts={method,headers:getHeaders()};if(body)opts.body=JSON.stringify(body);const res=await fetch(path,opts);return res.json();}

async function fetchKeys(isAdmin){
  try{
    const headers={'Content-Type':'application/json'};
    if(isAdmin)headers['x-admin-key']=adminKey;else headers['x-panel-token']=panelToken;
    const res=await fetch('/admin/keys',{headers});
    const data=await res.json();
    if(data.error)return false;
    keysData=data;renderTable();updateStats();return true;
  }catch{return false;}
}

async function fetchUsers(){const data=await api('/admin/users');if(!data.error){usersData=data;renderUsers();}}

function updateStats(){
  const vals=Object.values(keysData),now=new Date(),cutoff=new Date(Date.now()-30*60*1000);
  document.getElementById('s-total').textContent=vals.length;
  document.getElementById('s-active').textContent=vals.filter(k=>k.active&&!k.paused&&(!k.expiresAt||new Date(k.expiresAt)>now)&&k.firstActivated).length;
  document.getElementById('s-online').textContent=vals.filter(k=>k.lastUsed&&new Date(k.lastUsed)>=cutoff&&k.active).length;
  document.getElementById('s-paused').textContent=vals.filter(k=>k.paused).length;
  document.getElementById('s-revoked').textContent=vals.filter(k=>!k.active&&!k.paused).length;
  document.getElementById('s-expired').textContent=vals.filter(k=>k.active&&k.expiresAt&&new Date(k.expiresAt)<=now).length;
  document.getElementById('s-uses').textContent=vals.reduce((a,k)=>a+(k.activations||0),0);
}

function setFilter(mode,el){filterMode=mode;document.querySelectorAll('.ftab').forEach(b=>b.classList.remove('on'));el.classList.add('on');renderTable();}
function getStatus(k){const now=new Date();if(k.paused)return'paused';if(!k.active)return'revoked';if(k.expiresAt&&new Date(k.expiresAt)<=now)return'expired';return'active';}

function fmtExpiry(k){
  if(k.paused&&k.pausedTimeLeft){const ms=k.pausedTimeLeft,d=Math.floor(ms/86400000),h=Math.floor((ms%86400000)/3600000),m=Math.floor((ms%3600000)/60000);return'<span class="expiry-never">⏸️ '+d+'d '+h+'h '+m+'m frozen</span>';}
  if(k.pendingDuration&&!k.firstActivated)return'<span class="expiry-never">⏳ Starts on login ('+esc(k.duration||'')+')</span>';
  if(!k.expiresAt)return'<span class="expiry-never">∞ Lifetime</span>';
  const now=new Date(),exp=new Date(k.expiresAt),diff=exp-now;
  const dateStr=exp.toLocaleDateString()+' '+exp.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  if(diff<=0)return'<span class="expiry-exp">Expired</span>';
  const days=Math.floor(diff/86400000),hrs=Math.floor((diff%86400000)/3600000),mins=Math.floor((diff%3600000)/60000),secs=Math.floor((diff%60000)/1000);
  let countStr=days>0?days+'d '+hrs+'h '+mins+'m':hrs>0?hrs+'h '+mins+'m '+secs+'s':mins+'m '+secs+'s';
  const cls=days<=0&&hrs<1?'expiry-exp':days<=3?'expiry-soon':'expiry-ok';
  return'<span class="'+cls+'" title="'+dateStr+'">'+countStr+' left</span>';
}

function fmtDate(d){if(!d)return'<span style="color:var(--t3)">Never</span>';return new Date(d).toLocaleDateString()+' '+new Date(d).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});}
function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

function renderTable(){
  const search=document.getElementById('search').value.toLowerCase();
  const body=document.getElementById('keys-body');
  let entries=Object.entries(keysData);
  entries=entries.filter(([k,v])=>{
    const st=getStatus(v);
    if(filterMode!=='all'&&st!==filterMode)return false;
    if(search&&!k.toLowerCase().includes(search)&&!(v.note||'').toLowerCase().includes(search))return false;
    return true;
  });
  entries.sort((a,b)=>new Date(b[1].created)-new Date(a[1].created));
  if(!entries.length){body.innerHTML='<tr class="empty-row"><td colspan="8">No keys found</td></tr>';return;}
  body.innerHTML='';
  entries.forEach(([k,v])=>{
    const st=getStatus(v);
    const tr=document.createElement('tr');
    const hwidBadge=v.hwid?'<span class="badge locked">Locked</span>':'<span class="badge free">Free</span>';
    tr.innerHTML='<td><span class="key-mono" title="Click to copy">'+k+'</span></td>'
      +'<td><span class="note-col" title="'+esc(v.note||'')+'">'+esc(v.note||'-')+'</span></td>'
      +'<td><span class="badge '+st+'">'+st.charAt(0).toUpperCase()+st.slice(1)+'</span></td>'
      +'<td>'+hwidBadge+'</td>'
      +'<td>'+fmtExpiry(v)+'</td>'
      +'<td style="color:var(--purple)">'+(v.activations||0)+'</td>'
      +'<td style="color:var(--t3);font-size:11px">'+fmtDate(v.lastUsed)+'</td>'
      +'<td><div class="actions"></div></td>';
    tr.querySelector('.key-mono').addEventListener('click',()=>copyText(k));
    const acts=tr.querySelector('.actions');
    if(st==='paused'){
      const b1=document.createElement('button');b1.className='btn-activate';b1.textContent='Resume';b1.onclick=()=>resumeKey(k);acts.appendChild(b1);
      const b2=document.createElement('button');b2.className='btn-delete';b2.textContent='Delete';b2.onclick=()=>del(k);acts.appendChild(b2);
    }else if(st==='revoked'){
      const b1=document.createElement('button');b1.className='btn-activate';b1.textContent='Reactivate';b1.onclick=()=>reactivate(k);acts.appendChild(b1);
      const b2=document.createElement('button');b2.className='btn-delete';b2.textContent='Delete';b2.onclick=()=>del(k);acts.appendChild(b2);
    }else{
      const b1=document.createElement('button');b1.className='btn-revoke';b1.textContent='Revoke';b1.onclick=()=>revoke(k);acts.appendChild(b1);
      if(v.expiresAt){const b2=document.createElement('button');b2.className='btn-pause';b2.textContent='Pause';b2.onclick=()=>pauseKey(k);acts.appendChild(b2);}
      if(v.hwid){const b3=document.createElement('button');b3.className='btn-hwid';b3.textContent='Reset HWID';b3.onclick=()=>resetHwid(k);acts.appendChild(b3);}
      const b4=document.createElement('button');b4.className='btn-delete';b4.textContent='Delete';b4.onclick=()=>del(k);acts.appendChild(b4);
    }
    body.appendChild(tr);
  });
}

function renderUsers(){
  const body=document.getElementById('users-body');
  const entries=Object.entries(usersData);
  if(!entries.length){body.innerHTML='<tr class="empty-row"><td colspan="4">No panel users yet</td></tr>';return;}
  body.innerHTML='';
  entries.forEach(([u,v])=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td style="font-weight:600">'+esc(u)+'</td>'
      +'<td style="color:var(--t2)">'+esc(v.note||'-')+'</td>'
      +'<td><span class="badge '+(v.active?'active':'revoked')+'">'+(v.active?'Active':'Revoked')+'</span></td>'
      +'<td><div class="actions"></div></td>';
    const acts=tr.querySelector('.actions');
    if(v.active){const b1=document.createElement('button');b1.className='btn-revoke';b1.textContent='Revoke';b1.onclick=()=>revokeUser(u);acts.appendChild(b1);}
    const b2=document.createElement('button');b2.className='btn-delete';b2.textContent='Delete';b2.onclick=()=>deleteUser(u);acts.appendChild(b2);
    body.appendChild(tr);
  });
}

async function createKey(){
  const note=document.getElementById('c-note').value.trim(),duration=document.getElementById('c-days').value;
  const data=await api('/admin/keys/create','POST',{note,duration});
  if(data.key){
    document.getElementById('new-key-box').style.display='block';
    const el=document.getElementById('new-key-val');el.textContent=data.key;el.onclick=()=>copyText(data.key);
    copyText(data.key);toast('Key created + copied! ('+( data.duration||'Lifetime')+')','ok');
    await fetchKeys(isSuperAdmin);
  }else toast(data.error||'Error creating key','err');
}

async function revoke(key){if(!confirm('Revoke '+key+'?'))return;const data=await api('/admin/keys/revoke','POST',{key});if(data.ok){toast('Key revoked','ok');await fetchKeys(isSuperAdmin);}else toast('Error','err');}
async function reactivate(key){const data=await api('/admin/keys/reactivate','POST',{key});if(data.ok){toast('Key reactivated','ok');await fetchKeys(isSuperAdmin);}else toast('Error','err');}
async function resetHwid(key){if(!confirm('Reset HWID for '+key+'?'))return;const data=await api('/admin/keys/reset-hwid','POST',{key});if(data.ok){toast('HWID reset','ok');await fetchKeys(isSuperAdmin);}else toast('Error','err');}
async function del(key){if(!confirm('Permanently DELETE '+key+'?'))return;const data=await api('/admin/keys/delete','POST',{key});if(data.ok){toast('Key deleted','ok');await fetchKeys(isSuperAdmin);}else toast('Error','err');}

async function pauseKey(key){
  if(!confirm('Pause '+key+'? User will be kicked within 5 minutes.'))return;
  const keys=keysData[key];if(!keys)return;
  const timeLeft=keys.expiresAt?new Date(keys.expiresAt).getTime()-Date.now():0;
  if(timeLeft<=0){toast('Key already expired','err');return;}
  // Call revoke endpoint and store pause data locally (server handles it via Discord command)
  // For dashboard, just revoke — use Discord /pausekey for full pause functionality
  toast('Use /pausekey in Discord for full pause with timer freeze','ok');
}

async function resumeKey(key){
  // Resume is handled server-side via Discord /resumekey
  // Dashboard shows paused keys but resume via Discord bot
  toast('Use /resumekey '+key+' in Discord to resume with frozen timer','ok');
}

async function createUser(){
  const username=document.getElementById('u-name').value.trim(),password=document.getElementById('u-pass').value.trim(),note=document.getElementById('u-note').value.trim();
  if(!username||!password){toast('Username and password required','err');return;}
  const data=await api('/admin/users/create','POST',{username,password,note});
  if(data.ok){toast('Panel user created!','ok');document.getElementById('u-name').value='';document.getElementById('u-pass').value='';document.getElementById('u-note').value='';await fetchUsers();}
  else toast(data.error||'Error','err');
}

async function revokeUser(username){if(!confirm('Revoke '+username+'?'))return;const data=await api('/admin/users/revoke','POST',{username});if(data.ok){toast('User revoked','ok');await fetchUsers();}else toast('Error','err');}
async function deleteUser(username){if(!confirm('Delete '+username+'?'))return;const data=await api('/admin/users/delete','POST',{username});if(data.ok){toast('User deleted','ok');await fetchUsers();}else toast('Error','err');}

function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('Copied!','ok'));}
let tTimer;
function toast(msg,type='ok'){const el=document.createElement('div');el.className='toast '+type;el.textContent=msg;document.body.appendChild(el);clearTimeout(tTimer);tTimer=setTimeout(()=>el.remove(),2800);}

setInterval(()=>{if(adminKey||panelToken)fetchKeys(isSuperAdmin);},30000);
setInterval(()=>{if((adminKey||panelToken)&&Object.keys(keysData).length)renderTable();},1000);
</script>
</body>
</html>`);
});

// Connect to MongoDB first, then start server
connectDB().then(() => {
  app.listen(PORT, () => console.log('TokenSnipe server v4 running on port', PORT));
}).catch(e => {
  console.error('Failed to connect to MongoDB:', e);
  process.exit(1);
});
