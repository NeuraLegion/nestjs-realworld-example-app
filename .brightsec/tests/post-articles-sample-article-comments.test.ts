import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /articles/sample-article/comments', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['stored_xss', 'sqli', 'bopla', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['MySQL'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/articles/sample-article/comments`,
      body: {
        comment: {
          body: 'This is a sample comment.'
        }
      },
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <token>'
      }
    });
});