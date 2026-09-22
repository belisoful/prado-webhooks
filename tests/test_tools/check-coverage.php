<?php

/**
 * Fails when line coverage in a Clover report is below a threshold.
 *
 *     php tests/test_tools/check-coverage.php <clover.xml> <minimum-percent>
 *
 * PHPUnit can report coverage but cannot enforce a floor, so CI calls this after the coverage
 * run. Set the floor just below what the suite actually reaches, and raise it as tests land.
 */

$file = $argv[1] ?? '';
$minimum = (float) ($argv[2] ?? 0);
if ($file === '' || !is_file($file)) {
	fwrite(STDERR, "usage: check-coverage.php <clover.xml> <minimum-percent>\n");
	exit(2);
}

$xml = simplexml_load_file($file);
if ($xml === false) {
	fwrite(STDERR, "could not parse {$file}\n");
	exit(2);
}

$metrics = $xml->project->metrics ?? null;
if ($metrics === null) {
	fwrite(STDERR, "no project metrics in {$file}\n");
	exit(2);
}

$statements = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];
if ($statements === 0) {
	fwrite(STDERR, "no statements recorded in {$file}\n");
	exit(2);
}

$percent = $covered / $statements * 100;
printf("line coverage: %.2f%% (%d/%d), minimum %.2f%%\n", $percent, $covered, $statements, $minimum);
if ($percent + 0.0001 < $minimum) {
	fwrite(STDERR, "coverage is below the minimum\n");
	exit(1);
}
