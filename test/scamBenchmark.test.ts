import { analyzePersonalContent } from '../server/scamEngine.ts';

interface LabeledSample {
  id: string;
  category: string;
  expectedLabel: 'MALICIOUS' | 'BENIGN';
  text: string;
  inputType: 'message' | 'email' | 'job' | 'url';
}

const LABELED_DATASET: LabeledSample[] = [
  // --- Malicious Samples (True Positives) ---
  {
    id: 'mal-1',
    category: 'Banking / KYC Phishing',
    expectedLabel: 'MALICIOUS',
    text: 'Your State Bank account KYC is suspended. Submit OTP and NetBanking password immediately to avoid permanent deactivation.',
    inputType: 'message'
  },
  {
    id: 'mal-2',
    category: 'Recruitment & Advance Fee',
    expectedLabel: 'MALICIOUS',
    text: 'Congratulations! You are selected for part time work from home. Registration fee of ₹2,500 required before laptop dispatch at career-update.xyz.',
    inputType: 'job'
  },
  {
    id: 'mal-3',
    category: 'Utility Disconnection Extortion',
    expectedLabel: 'MALICIOUS',
    text: 'Dear consumer, electricity disconnected tonight at 9:30 PM due to unpaid bill. Pay immediately to avoid power will be cut.',
    inputType: 'message'
  },
  {
    id: 'mal-4',
    category: 'Remote Access / Screen Sharing Fraud',
    expectedLabel: 'MALICIOUS',
    text: 'Tech support alert: Bank transaction failed. Install AnyDesk and share screen to process your immediate refund.',
    inputType: 'message'
  },
  {
    id: 'mal-5',
    category: 'Telegram Task & Fake Payout',
    expectedLabel: 'MALICIOUS',
    text: 'Earn 10000 daily with YouTube video like and telegram task. No experience required. Guaranteed stipend.',
    inputType: 'job'
  },
  {
    id: 'mal-6',
    category: 'UPI Extortion & Fake Verification',
    expectedLabel: 'MALICIOUS',
    text: 'URGENT: Legal action initiated. Pay ₹5,000 verification fee immediately to upi-officer@okaxis to clear warrant.',
    inputType: 'message'
  },

  // --- Benign Samples (True Negatives) ---
  {
    id: 'ben-1',
    category: 'Workplace Coordination',
    expectedLabel: 'BENIGN',
    text: 'Hi team, please find attached the meeting minutes and project timeline discussed during today sprint review.',
    inputType: 'email'
  },
  {
    id: 'ben-2',
    category: 'E-commerce Shipment Update',
    expectedLabel: 'BENIGN',
    text: 'Your order #84920 has shipped via BlueDart. Track package status on your account dashboard.',
    inputType: 'message'
  },
  {
    id: 'ben-3',
    category: 'Calendar Planning',
    expectedLabel: 'BENIGN',
    text: 'Quarterly roadmap planning session scheduled for Thursday at 3 PM in Conference Room B.',
    inputType: 'email'
  },
  {
    id: 'ben-4',
    category: 'Educational Notification',
    expectedLabel: 'BENIGN',
    text: 'Reminder: Midterm exam schedule has been published on the student portal. Please check your assigned room.',
    inputType: 'email'
  },
  {
    id: 'ben-5',
    category: 'Product Inquiry',
    expectedLabel: 'BENIGN',
    text: 'Can you please let me know if your API supports pagination and rate limiting for audit log queries?',
    inputType: 'email'
  },
  {
    id: 'ben-6',
    category: 'Unfamiliar Domain without Malicious Triggers',
    expectedLabel: 'BENIGN',
    text: 'Please visit partner-docs-review.org to read the updated community contribution guidelines.',
    inputType: 'url'
  }
];

export async function runScamBenchmark() {
  console.log('\n========================================');
  console.log('CYBERRAKSHAK AI SCAM ANALYSIS BENCHMARK');
  console.log('========================================\n');
  console.log(`Evaluating ${LABELED_DATASET.length} labeled ground-truth samples...\n`);

  let tp = 0; // True Positives
  let fp = 0; // False Positives
  let tn = 0; // True Negatives
  let fn = 0; // False Negatives

  for (const sample of LABELED_DATASET) {
    const analysis = await analyzePersonalContent(sample.text, sample.inputType);
    const isClassifiedMalicious = analysis.riskLevel === 'High Risk' || analysis.riskLevel === 'Critical Risk';

    if (sample.expectedLabel === 'MALICIOUS') {
      if (isClassifiedMalicious) {
        tp++;
        console.log(`  ✓ TP [${sample.id}]: ${sample.category} -> ${analysis.riskLevel} (${analysis.score}/100)`);
      } else {
        fn++;
        console.error(`  ✗ FN [${sample.id}]: ${sample.category} -> Missed! Classified as ${analysis.riskLevel} (${analysis.score}/100)`);
      }
    } else {
      if (!isClassifiedMalicious) {
        tn++;
        console.log(`  ✓ TN [${sample.id}]: ${sample.category} -> ${analysis.riskLevel} (${analysis.score}/100)`);
      } else {
        fp++;
        console.error(`  ✗ FP [${sample.id}]: ${sample.category} -> False Positive! Classified as ${analysis.riskLevel} (${analysis.score}/100)`);
      }
    }
  }

  const accuracy = (tp + tn) / LABELED_DATASET.length;
  const precision = tp / (tp + fp);
  const recall = tp / (tp + fn);
  const f1 = (2 * precision * recall) / (precision + recall);

  console.log('\n----------------------------------------');
  console.log(`BENCHMARK METRICS:`);
  console.log(`  Total Labeled Samples : ${LABELED_DATASET.length}`);
  console.log(`  True Positives (TP)   : ${tp}`);
  console.log(`  True Negatives (TN)   : ${tn}`);
  console.log(`  False Positives (FP)  : ${fp}`);
  console.log(`  False Negatives (FN)  : ${fn}`);
  console.log(`  Accuracy              : ${(accuracy * 100).toFixed(1)}%`);
  console.log(`  Precision             : ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall                : ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1-Score              : ${(f1 * 100).toFixed(1)}%`);
  console.log('----------------------------------------\n');

  if (fp > 0 || fn > 0) {
    console.error('Benchmark failed: Discovered misclassifications in labeled benchmark dataset.');
    process.exit(1);
  }
}

// Run if called directly
if (process.argv[1]?.includes('scamBenchmark.test')) {
  runScamBenchmark().catch(err => {
    console.error('Benchmark error:', err);
    process.exit(1);
  });
}
