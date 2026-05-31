import { input } from '@inquirer/prompts';
import chalk from 'chalk';
import boxen from 'boxen';
import { loadConfig, saveConfig, verifyAuditLog } from '../utils/secure-config.js';

export async function configCommand() {
  chalk.level = 3;
  console.log(boxen(
    chalk.hex('#00e6b4').bold('Aegis Configuration') + '\n' +
    chalk.hex('#7a90a8')('API key is encrypted at rest (AES-256-GCM) in ~/.aegis/config.enc\n') +
    chalk.hex('#7a90a8')('Enterprise: prefer setting ANTHROPIC_API_KEY via your secrets manager,\nor use --offline to never transmit source code.'),
    { padding: 1, borderColor: '#162030', borderStyle: 'round' }
  ));

  const current = loadConfig();
  const apiKey = await input({
    message: chalk.white('Anthropic API key') + chalk.hex('#4a5a6a')(' (console.anthropic.com):'),
    default: current.apiKey ? '***' + current.apiKey.slice(-6) : undefined,
  });
  const finalKey = apiKey.startsWith('***') ? current.apiKey : apiKey.trim();
  saveConfig({ ...current, apiKey: finalKey });

  console.log('\n' + chalk.hex('#00e6b4')('OK ') + chalk.white('Config encrypted and saved.'));

  const audit = verifyAuditLog();
  console.log(chalk.hex('#7a90a8')(`  Audit log: ${audit.entries} entries, integrity ${audit.valid ? chalk.hex('#00e6b4')('VALID') : chalk.hex('#ff4560')('BROKEN at #' + audit.brokenAt)}`) + '\n');
}
