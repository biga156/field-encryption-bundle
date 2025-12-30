<?php

declare(strict_types=1);

namespace Caeligo\FieldEncryptionBundle\Command;

use Caeligo\FieldEncryptionBundle\Service\FieldEncryptionService;
use Caeligo\FieldEncryptionBundle\Service\KeyRotationService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Console command to rotate encryption keys for all encrypted entities.
 *
 * This command guides users through the key rotation process or allows
 * advanced users to run rotation directly with specific options.
 *
 * Usage:
 *     php bin/console field-encryption:rotate-keys --wizard
 *     php bin/console field-encryption:rotate-keys --batch-size=100
 *     php bin/console field-encryption:rotate-keys --continue
 *     php bin/console field-encryption:rotate-keys --dry-run
 *
 * @author Bíró Gábor (biga156)
 */
#[AsCommand(
    name: 'field-encryption:rotate-keys',
    description: 'Rotate encryption keys for all encrypted entities',
)]
class RotateEncryptionKeyCommand extends Command
{
    public function __construct(
        private KeyRotationService $keyRotationService,
        private EntityManagerInterface $entityManager,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'wizard',
                'w',
                InputOption::VALUE_NONE,
                'Run interactive wizard that guides through the entire key rotation process'
            )
            ->addOption(
                'batch-size',
                'b',
                InputOption::VALUE_REQUIRED,
                'Number of entities to process per batch',
                '100'
            )
            ->addOption(
                'continue',
                'c',
                InputOption::VALUE_NONE,
                'Continue a previously interrupted rotation'
            )
            ->addOption(
                'dry-run',
                'd',
                InputOption::VALUE_NONE,
                'Simulate the rotation without making changes'
            )
            ->addOption(
                'entity',
                'e',
                InputOption::VALUE_REQUIRED,
                'Process only a specific entity class'
            )
            ->setHelp(<<<'HELP'
The <info>%command.name%</info> command rotates encryption keys for all entities
with encrypted fields.

<comment>Interactive Wizard (Recommended):</comment>
    <info>php %command.full_name% --wizard</info>

The wizard will guide you through:
1. Generating a new encryption key
2. Updating your configuration
3. Running the rotation process
4. Cleaning up old keys

<comment>Direct Rotation (Advanced):</comment>
    <info>php %command.full_name% --batch-size=100</info>

Assumes you have already:
- Generated a new key
- Updated field_encryption.encryption_key with the new key
- Added the old key to field_encryption.previous_keys

<comment>Continue Interrupted Rotation:</comment>
    <info>php %command.full_name% --continue</info>

<comment>Dry Run (Preview):</comment>
    <info>php %command.full_name% --dry-run</info>

<comment>Process Specific Entity:</comment>
    <info>php %command.full_name% --entity="App\Entity\User"</info>
HELP);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if ($input->getOption('wizard')) {
            return $this->runWizard($input, $output, $io);
        }

        return $this->runRotation($input, $output, $io);
    }

    /**
     * Run the interactive wizard.
     */
    private function runWizard(InputInterface $input, OutputInterface $output, SymfonyStyle $io): int
    {
        $io->title('🔐 Field Encryption Key Rotation Wizard');

        // Step 1: Generate new key
        $io->section('Step 1/4: Generate new encryption key');

        $newKey = FieldEncryptionService::generateKey();

        $io->success('Generated new key: ' . $newKey);

        $io->warning('ACTION REQUIRED: Store this key securely!');

        $io->text([
            'For .env.local, add:',
            '  <info>FIELD_ENCRYPTION_KEY_NEW=' . $newKey . '</info>',
            '',
            'For Vault/Secrets Manager, create:',
            '  <info>field_encryption_key_new = ' . $newKey . '</info>',
        ]);

        if (!$io->confirm('Have you stored the new key securely?', false)) {
            $io->error('Key rotation cancelled. Please store the key and try again.');
            return Command::FAILURE;
        }

        // Step 2: Verify configuration
        $io->section('Step 2/4: Update configuration');

        $io->text([
            'Update your <info>config/packages/field_encryption.yaml</info>:',
            '',
            '<info>field_encryption:</info>',
            '<info>    encryption_key: \'%env(FIELD_ENCRYPTION_KEY_NEW)%\'</info>',
            '<info>    key_version: 2  # Increment from current version</info>',
            '<info>    previous_keys:</info>',
            '<info>        1: \'%env(FIELD_ENCRYPTION_KEY)%\'  # Your old key</info>',
            '',
            'Then clear the cache:',
            '  <info>php bin/console cache:clear</info>',
        ]);

        if (!$io->confirm('Have you updated the configuration and cleared the cache?', false)) {
            $io->error('Key rotation cancelled. Please update configuration and try again.');
            return Command::FAILURE;
        }

        // Step 3: Run rotation
        $io->section('Step 3/4: Rotate encrypted data');

        $batchSize = (int) $input->getOption('batch-size');
        $dryRun = $input->getOption('dry-run');

        $entityClasses = $this->keyRotationService->getEncryptedEntityClasses($this->entityManager);

        if (empty($entityClasses)) {
            $io->warning('No entities with encrypted fields found.');
            return Command::SUCCESS;
        }

        $io->text('Found ' . count($entityClasses) . ' entity type(s) with encrypted fields:');
        foreach ($entityClasses as $class) {
            $count = $this->getEntityCount($class);
            $io->text('  - ' . $class . ' (' . $count . ' records)');
        }

        if (!$io->confirm('Proceed with rotation?', true)) {
            $io->warning('Key rotation cancelled.');
            return Command::FAILURE;
        }

        $totalStats = ['processed' => 0, 'skipped' => 0, 'errors' => 0];

        foreach ($entityClasses as $entityClass) {
            $io->text('Processing: ' . $entityClass);

            $count = $this->getEntityCount($entityClass);
            $progressBar = new ProgressBar($output, $count);
            $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% %elapsed:6s%/%estimated:-6s%');
            $progressBar->start();

            if ($dryRun) {
                // Simulate progress
                for ($i = 0; $i < $count; $i++) {
                    $progressBar->advance();
                    usleep(1000); // Small delay for visual feedback
                }
                $stats = ['processed' => $count, 'skipped' => 0, 'errors' => 0];
            } else {
                $stats = $this->keyRotationService->rotateKeysForEntity(
                    $this->entityManager,
                    $entityClass,
                    $batchSize,
                    function (int $processed, int $total) use ($progressBar) {
                        $progressBar->setProgress($processed);
                    },
                    $this->getProjectDir(),
                );
            }

            $progressBar->finish();
            $io->newLine(2);

            $totalStats['processed'] += $stats['processed'];
            $totalStats['skipped'] += $stats['skipped'];
            $totalStats['errors'] += $stats['errors'];
        }

        if ($dryRun) {
            $io->note('DRY RUN - No changes were made');
        }

        $io->success(sprintf(
            'Rotation complete: %d processed, %d skipped, %d errors',
            $totalStats['processed'],
            $totalStats['skipped'],
            $totalStats['errors']
        ));

        // Step 4: Cleanup instructions
        $io->section('Step 4/4: Cleanup');

        $io->text([
            '<comment>ACTION REQUIRED: Update your configuration for production!</comment>',
            '',
            '1. Rename the new key as primary:',
            '   <info>FIELD_ENCRYPTION_KEY=<your-new-key></info>',
            '',
            '2. Move old key to previous_keys (keep for 30 days recommended):',
            '   <info>FIELD_ENCRYPTION_KEY_V1=<your-old-key></info>',
            '',
            '3. Update config/packages/field_encryption.yaml:',
            '   <info>field_encryption:</info>',
            '   <info>    encryption_key: \'%env(FIELD_ENCRYPTION_KEY)%\'</info>',
            '   <info>    previous_keys:</info>',
            '   <info>        1: \'%env(FIELD_ENCRYPTION_KEY_V1)%\'</info>',
            '',
            '4. After 30 days, remove the old key from previous_keys',
        ]);

        $io->success('Key rotation completed successfully!');

        return Command::SUCCESS;
    }

    /**
     * Run rotation directly (non-wizard mode).
     */
    private function runRotation(InputInterface $input, OutputInterface $output, SymfonyStyle $io): int
    {
        $batchSize = (int) $input->getOption('batch-size');
        $continue = $input->getOption('continue');
        $dryRun = $input->getOption('dry-run');
        $specificEntity = $input->getOption('entity');

        // Check for pending progress
        $pendingProgress = $this->keyRotationService->getPendingProgress($this->getProjectDir());

        if (!$continue && !empty($pendingProgress)) {
            $io->warning('Found interrupted rotation in progress. Use --continue to resume or delete var/field_encryption_rotation_progress.json to start fresh.');
            foreach ($pendingProgress as $class => $lastId) {
                $io->text('  - ' . $class . ' (last processed: ' . $lastId . ')');
            }
            return Command::FAILURE;
        }

        // Get entity classes to process
        if ($specificEntity !== null) {
            $entityClasses = [$specificEntity];
        } else {
            $entityClasses = $this->keyRotationService->getEncryptedEntityClasses($this->entityManager);
        }

        if (empty($entityClasses)) {
            $io->warning('No entities with encrypted fields found.');
            return Command::SUCCESS;
        }

        $io->title('Field Encryption Key Rotation');

        if ($dryRun) {
            $io->note('DRY RUN MODE - No changes will be made');
        }

        $totalStats = ['processed' => 0, 'skipped' => 0, 'errors' => 0];

        foreach ($entityClasses as $entityClass) {
            $count = $this->getEntityCount($entityClass);
            $io->section($entityClass . ' (' . $count . ' records)');

            $progressBar = new ProgressBar($output, $count);
            $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% %elapsed:6s%/%estimated:-6s%');
            $progressBar->start();

            if ($dryRun) {
                for ($i = 0; $i < $count; $i++) {
                    $progressBar->advance();
                    usleep(1000);
                }
                $stats = ['processed' => $count, 'skipped' => 0, 'errors' => 0];
            } else {
                $stats = $this->keyRotationService->rotateKeysForEntity(
                    $this->entityManager,
                    $entityClass,
                    $batchSize,
                    function (int $processed, int $total) use ($progressBar) {
                        $progressBar->setProgress($processed);
                    },
                    $this->getProjectDir(),
                );
            }

            $progressBar->finish();
            $io->newLine();

            $io->text(sprintf(
                '  Processed: %d | Skipped: %d | Errors: %d',
                $stats['processed'],
                $stats['skipped'],
                $stats['errors']
            ));

            $totalStats['processed'] += $stats['processed'];
            $totalStats['skipped'] += $stats['skipped'];
            $totalStats['errors'] += $stats['errors'];
        }

        $io->newLine();

        if ($totalStats['errors'] > 0) {
            $io->warning(sprintf(
                'Rotation completed with errors: %d processed, %d skipped, %d errors',
                $totalStats['processed'],
                $totalStats['skipped'],
                $totalStats['errors']
            ));
            return Command::FAILURE;
        }

        $io->success(sprintf(
            'Rotation completed: %d processed, %d skipped',
            $totalStats['processed'],
            $totalStats['skipped']
        ));

        return Command::SUCCESS;
    }

    /**
     * Get entity count for a class.
     */
    private function getEntityCount(string $entityClass): int
    {
        return (int) $this->entityManager->createQueryBuilder()
            ->select('COUNT(e.id)')
            ->from($entityClass, 'e')
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * Get project directory.
     */
    private function getProjectDir(): string
    {
        // Try to get from kernel if available
        return getcwd();
    }
}
