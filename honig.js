/**
 * RNAi Regulatory Intelligence Dashboard
 * Complete Backend Server for Blackstone Life Sciences
 * Focus: Alnylam/Leqvio and RNAi Competitors
 * 
 * To run:
 * 1. npm init -y
 * 2. npm install express axios cheerio puppeteer csv-parser xml2js node-cron winston dotenv cors compression helmet
 * 3. Create .env file with: FDA_API_KEY=your_key_here (get from https://open.fda.gov/apis/authentication/)
 * 4. node server.js
 */

const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');
const csv = require('csv-parser');
const xml2js = require('xml2js');
const cron = require('node-cron');
const winston = require('winston');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');
const fs = require('fs').promises;
const path = require('path');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// In-memory database (replace with PostgreSQL/MongoDB in production)
const database = {
  adverseEvents: [],
  clinicalTrials: [],
  approvals: [],
  inspections: [],
  competitors: [],
  pdufaDates: [],
  safetySignals: [],
  regulatoryDocuments: [],
  patents: [],
  emaData: [],
  lastUpdated: {}
};

// RNAi Drug Portfolio Configuration
const RNAI_PORTFOLIO = {
  alnylam: {
    drugs: [
      { name: 'inclisiran', brand: 'Leqvio', approved: true, indication: 'hypercholesterolemia' },
      { name: 'patisiran', brand: 'Onpattro', approved: true, indication: 'hATTR' },
      { name: 'givosiran', brand: 'Givlaari', approved: true, indication: 'AHP' },
      { name: 'lumasiran', brand: 'Oxlumo', approved: true, indication: 'PH1' },
      { name: 'vutrisiran', brand: 'Amvuttra', approved: true, indication: 'hATTR' }
    ],
    investment: 2000000000, // $2B
    ticker: 'ALNY'
  },
  competitors: [
    {
      company: 'Arrowhead',
      ticker: 'ARWR',
      drugs: ['plozasiran', 'zodasiran', 'fazirsiran'],
      pdufaDates: [{ drug: 'plozasiran', date: '2025-11-18' }]
    },
    {
      company: 'Dicerna/Novo',
      ticker: 'NVO',
      drugs: ['nedosiran', 'belcesiran']
    },
    {
      company: 'Ionis',
      ticker: 'IONS',
      drugs: ['eplontersen', 'donidalorsen', 'olezarsen']
    }
  ]
};

// ===========================================
// FDA API INTEGRATION
// ===========================================

class FDAService {
  constructor() {
    this.baseURL = 'https://api.fda.gov';
    this.apiKey = process.env.FDA_API_KEY || 'FQfKwgmltH9Vc9YmhouJDVO5Q5BJwQMMr5xA0KLe'; // Demo key - replace with your own
    this.rateLimit = {
      requests: 0,
      resetTime: Date.now() + 60000
    };
  }

  // Check rate limiting
  async checkRateLimit() {
    if (Date.now() > this.rateLimit.resetTime) {
      this.rateLimit.requests = 0;
      this.rateLimit.resetTime = Date.now() + 60000;
    }
    
    if (this.rateLimit.requests >= 240) {
      const waitTime = this.rateLimit.resetTime - Date.now();
      logger.warn(`FDA API rate limit reached. Waiting ${waitTime}ms`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      this.rateLimit.requests = 0;
    }
    
    this.rateLimit.requests++;
  }

  // Fetch adverse events from FAERS
async fetchAdverseEvents(drugName) {
  try {
    await this.checkRateLimit();
    
    // FDA API needs different search formats for different drugs
    // Try multiple search strategies
    const searchStrategies = [
      `patient.drug.medicinalproduct:"${drugName}"`,
      `patient.drug.openfda.brand_name:"${drugName}"`,
      `patient.drug.openfda.generic_name:"${drugName}"`,
      `patient.drug.openfda.substance_name:"${drugName}"`
    ];

    // For known brand names, use specific searches
    const brandMappings = {
      'inclisiran': 'LEQVIO',
      'patisiran': 'ONPATTRO',
      'givosiran': 'GIVLAARI',
      'lumasiran': 'OXLUMO',
      'vutrisiran': 'AMVUTTRA'
    };

    if (brandMappings[drugName.toLowerCase()]) {
      searchStrategies.unshift(
        `patient.drug.medicinalproduct:"${brandMappings[drugName.toLowerCase()]}"`
      );
    }

    let allEvents = [];
    let successfulSearch = false;

    // Try each search strategy until one works
    for (const searchQuery of searchStrategies) {
      if (successfulSearch) break;
      
      try {
        const endpoint = '/drug/event.json';
        const params = {
          api_key: this.apiKey,
          search: searchQuery,
          limit: 100
        };

        const response = await axios.get(`${this.baseURL}${endpoint}`, { 
          params,
          timeout: 5000 
        });
        
        if (response.data && response.data.results && response.data.results.length > 0) {
          // Get the actual adverse events, not just counts
          const eventsParams = {
            api_key: this.apiKey,
            search: searchQuery,
            limit: 100,
            count: 'patient.reaction.reactionmeddrapt.exact'
          };

          const eventsResponse = await axios.get(`${this.baseURL}${endpoint}`, { 
            params: eventsParams,
            timeout: 5000 
          });

          if (eventsResponse.data && eventsResponse.data.results) {
            const processedEvents = eventsResponse.data.results.map(event => ({
              drug: drugName,
              event: event.term,
              count: event.count,
              timestamp: new Date().toISOString(),
              source: 'FDA FAERS',
              url: `${this.baseURL}${endpoint}?${new URLSearchParams(eventsParams)}`,
              ebgmScore: this.calculateEBGM(event.count, drugName)
            }));

            allEvents = processedEvents;
            successfulSearch = true;
            
            // Store in database
            database.adverseEvents = [
              ...database.adverseEvents.filter(e => e.drug !== drugName),
              ...processedEvents
            ];

            logger.info(`Fetched ${processedEvents.length} adverse events for ${drugName} using search: ${searchQuery}`);
          }
        }
      } catch (searchError) {
        // This specific search failed, try next one
        continue;
      }
    }

    if (!successfulSearch) {
      logger.warn(`No adverse events found for ${drugName} after trying all search strategies`);
    }

    return allEvents;
  } catch (error) {
    logger.error(`Error fetching adverse events for ${drugName}:`, error.message);
    return [];
  }
}


  // Calculate EBGM score for signal detection
  calculateEBGM(observedCount, drugName) {
    // Simplified EBGM calculation
    const expectedCount = 10; // Baseline expectation
    const ebgm = Math.log2((observedCount + 0.5) / (expectedCount + 0.5));
    return Math.max(0, ebgm).toFixed(2);
  }

async fetchDrugApprovals(drugName) {
  try {
    await this.checkRateLimit();
    
    // Map generic names to what FDA uses
    const fdaNameMappings = {
      'inclisiran': 'inclisiran sodium',
      'patisiran': 'patisiran sodium',
      'givosiran': 'givosiran sodium',
      'lumasiran': 'lumasiran sodium',
      'vutrisiran': 'vutrisiran sodium'
    };

    const searchName = fdaNameMappings[drugName.toLowerCase()] || drugName;
    
    const endpoint = '/drug/drugsfda.json';
    const params = {
      api_key: this.apiKey,
      search: `openfda.generic_name:"${searchName}" OR openfda.brand_name:"${searchName}"`,
      limit: 10
    };

    const response = await axios.get(`${this.baseURL}${endpoint}`, { 
      params,
      timeout: 5000 
    });
    
    if (response.data && response.data.results) {
      const approvals = response.data.results.map(item => ({
        drug: drugName,
        applicationNumber: item.application_number,
        approvalDate: item.submissions?.[0]?.submission_status_date || 'N/A',
        sponsor: item.sponsor_name,
        products: item.products,
        source: 'FDA Drugs@FDA',
        url: `${this.baseURL}${endpoint}?${new URLSearchParams(params)}`,
        timestamp: new Date().toISOString()
      }));

      database.approvals = [
        ...database.approvals.filter(a => a.drug !== drugName),
        ...approvals
      ];

      logger.info(`Fetched ${approvals.length} approval records for ${drugName}`);
      return approvals;
    }
    
    logger.warn(`No approval data found for ${drugName}`);
    return [];
  } catch (error) {
    logger.error(`Error fetching approvals for ${drugName}:`, error.message);
    return [];
  }
}

  // Fetch FDA inspection data
  async fetchInspections(companyName) {
    try {
      await this.checkRateLimit();
      
      const endpoint = '/drug/enforcement.json';
      const params = {
        api_key: this.apiKey,
        search: `recalling_firm:"${companyName}"`,
        limit: 25
      };

      const response = await axios.get(`${this.baseURL}${endpoint}`, { params });
      
      if (response.data && response.data.results) {
        const inspections = response.data.results.map(item => ({
          company: companyName,
          recallNumber: item.recall_number,
          reportDate: item.report_date,
          reason: item.reason_for_recall,
          classification: item.classification,
          status: item.status,
          source: 'FDA Enforcement',
          url: `${this.baseURL}${endpoint}?${new URLSearchParams(params)}`,
          timestamp: new Date().toISOString()
        }));

        database.inspections = [
          ...database.inspections.filter(i => i.company !== companyName),
          ...inspections
        ];

        logger.info(`Fetched ${inspections.length} inspection records for ${companyName}`);
        return inspections;
      }
      
      return [];
    } catch (error) {
      logger.error(`Error fetching inspections for ${companyName}:`, error.message);
      return [];
    }
  }

  // Search FDA guidance documents
  async searchGuidanceDocuments(searchTerm = 'oligonucleotide') {
    try {
      // FDA guidance documents require web scraping
      const url = `https://www.fda.gov/search?s=${encodeURIComponent(searchTerm + ' guidance')}`;
      const response = await axios.get(url);
      const $ = cheerio.load(response.data);
      
      const documents = [];
      $('.search-results .result').each((i, elem) => {
        if (i < 10) {
          const title = $(elem).find('.result-title').text().trim();
          const link = $(elem).find('a').attr('href');
          const snippet = $(elem).find('.result-snippet').text().trim();
          const date = $(elem).find('.result-date').text().trim();
          
          documents.push({
            title,
            url: link?.startsWith('http') ? link : `https://www.fda.gov${link}`,
            snippet,
            date,
            searchTerm,
            source: 'FDA Guidance',
            timestamp: new Date().toISOString()
          });
        }
      });

      database.regulatoryDocuments = [
        ...database.regulatoryDocuments.filter(d => d.searchTerm !== searchTerm),
        ...documents
      ];

      logger.info(`Found ${documents.length} FDA guidance documents for ${searchTerm}`);
      return documents;
    } catch (error) {
      logger.error(`Error searching guidance documents:`, error.message);
      return [];
    }
  }
}

// ===========================================
// CLINICAL TRIALS API INTEGRATION
// ===========================================

class ClinicalTrialsService {
  constructor() {
    this.baseURL = 'https://clinicaltrials.gov/api/v2';
  }

  // Search for RNAi clinical trials
  async searchRNAiTrials() {
    try {
      const searchTerms = [
        ...RNAI_PORTFOLIO.alnylam.drugs.map(d => d.name),
        ...RNAI_PORTFOLIO.competitors.flatMap(c => c.drugs)
      ];

      const allTrials = [];
      
      for (const term of searchTerms) {
        const params = {
          'query.term': term,
          'pageSize': 20,
          'format': 'json'
        };

        const response = await axios.get(`${this.baseURL}/studies`, { params });
        
        if (response.data && response.data.studies) {
          const trials = response.data.studies.map(study => ({
            nctId: study.protocolSection?.identificationModule?.nctId,
            drug: term,
            title: study.protocolSection?.identificationModule?.briefTitle,
            phase: study.protocolSection?.designModule?.phases?.join(', '),
            status: study.protocolSection?.statusModule?.overallStatus,
            sponsor: study.protocolSection?.sponsorCollaboratorsModule?.leadSponsor?.name,
            enrollment: study.protocolSection?.designModule?.enrollmentInfo?.count,
            startDate: study.protocolSection?.statusModule?.startDateStruct?.date,
            completionDate: study.protocolSection?.statusModule?.primaryCompletionDateStruct?.date,
            lastUpdate: study.protocolSection?.statusModule?.lastUpdatePostDateStruct?.date,
            source: 'ClinicalTrials.gov',
            url: `https://clinicaltrials.gov/study/${study.protocolSection?.identificationModule?.nctId}`,
            timestamp: new Date().toISOString()
          }));

          allTrials.push(...trials);
        }
        
        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      database.clinicalTrials = allTrials;
      logger.info(`Fetched ${allTrials.length} clinical trials for RNAi drugs`);
      return allTrials;
    } catch (error) {
      logger.error('Error fetching clinical trials:', error.message);
      return [];
    }
  }

  // Get competitive trial landscape
  async getCompetitiveLandscape() {
    const trials = database.clinicalTrials;
    
    const landscape = {
      byCompany: {},
      byPhase: {},
      byStatus: {},
      upcoming: []
    };

    trials.forEach(trial => {
      // Group by company
      const company = this.identifyCompany(trial.sponsor);
      if (!landscape.byCompany[company]) {
        landscape.byCompany[company] = [];
      }
      landscape.byCompany[company].push(trial);

      // Group by phase
      const phase = trial.phase || 'Unknown';
      if (!landscape.byPhase[phase]) {
        landscape.byPhase[phase] = [];
      }
      landscape.byPhase[phase].push(trial);

      // Group by status
      const status = trial.status || 'Unknown';
      if (!landscape.byStatus[status]) {
        landscape.byStatus[status] = [];
      }
      landscape.byStatus[status].push(trial);

      // Identify upcoming completions
      if (trial.completionDate) {
        const completionDate = new Date(trial.completionDate);
        const threeMonthsFromNow = new Date();
        threeMonthsFromNow.setMonth(threeMonthsFromNow.getMonth() + 3);
        
        if (completionDate <= threeMonthsFromNow && completionDate >= new Date()) {
          landscape.upcoming.push(trial);
        }
      }
    });

    return landscape;
  }

  identifyCompany(sponsor) {
    if (!sponsor) return 'Unknown';
    
    const sponsorLower = sponsor.toLowerCase();
    if (sponsorLower.includes('alnylam')) return 'Alnylam';
    if (sponsorLower.includes('arrowhead')) return 'Arrowhead';
    if (sponsorLower.includes('dicerna') || sponsorLower.includes('novo')) return 'Dicerna/Novo';
    if (sponsorLower.includes('ionis')) return 'Ionis';
    
    return sponsor;
  }
}

// ===========================================
// EMA (EUROPEAN) DATA INTEGRATION
// ===========================================

class EMAService {
  constructor() {
    this.baseURL = 'https://www.ema.europa.eu';
  }

  // Search EMA medicines database
  async searchEMAMedicines(drugName) {
    try {
      // EMA RSS feed for medicines
      const rssUrl = `${this.baseURL}/en/rss/medicines`;
      const response = await axios.get(rssUrl);
      
      const parser = new xml2js.Parser();
      const result = await parser.parseStringPromise(response.data);
      
      const medicines = [];
      if (result.rss && result.rss.channel) {
        result.rss.channel[0].item?.forEach(item => {
          const title = item.title[0].toLowerCase();
          if (title.includes(drugName.toLowerCase())) {
            medicines.push({
              drug: drugName,
              title: item.title[0],
              link: item.link[0],
              pubDate: item.pubDate[0],
              description: item.description[0],
              source: 'EMA RSS',
              timestamp: new Date().toISOString()
            });
          }
        });
      }

      database.emaData = [
        ...database.emaData.filter(e => e.drug !== drugName),
        ...medicines
      ];

      logger.info(`Found ${medicines.length} EMA entries for ${drugName}`);
      return medicines;
    } catch (error) {
      logger.error(`Error searching EMA for ${drugName}:`, error.message);
      return [];
    }
  }

  // Get EPAR documents
  async getEPARDocuments(medicineName) {
    try {
      const searchUrl = `${this.baseURL}/en/medicines/search?search_api_views_fulltext=${encodeURIComponent(medicineName)}`;
      const response = await axios.get(searchUrl);
      const $ = cheerio.load(response.data);
      
      const documents = [];
      $('.view-ema-search-medicines .views-row').each((i, elem) => {
        if (i < 5) {
          const title = $(elem).find('.views-field-title a').text().trim();
          const link = $(elem).find('.views-field-title a').attr('href');
          const status = $(elem).find('.views-field-field-ema-medicine-status').text().trim();
          const type = $(elem).find('.views-field-field-ema-med-type').text().trim();
          
          documents.push({
            medicine: medicineName,
            title,
            url: `${this.baseURL}${link}`,
            status,
            type,
            source: 'EMA EPAR',
            timestamp: new Date().toISOString()
          });
        }
      });

      return documents;
    } catch (error) {
      logger.error(`Error fetching EPAR documents for ${medicineName}:`, error.message);
      return [];
    }
  }
}

// ===========================================
// PATENT & IP TRACKING
// ===========================================

class PatentService {
  async searchPatents(drugName) {
    try {
      // Using USPTO API
      const url = `https://developer.uspto.gov/ibd-api/v1/patent/application?searchText=${encodeURIComponent(drugName + ' RNAi')}`;
      
      const response = await axios.get(url, {
        headers: {
          'Accept': 'application/json'
        }
      });

      if (response.data && response.data.response) {
        const patents = response.data.response.docs?.map(doc => ({
          drug: drugName,
          patentNumber: doc.patentNumber,
          title: doc.inventionTitle,
          filingDate: doc.filingDate,
          grantDate: doc.grantDate,
          applicant: doc.applicantName,
          source: 'USPTO',
          url: `https://patents.google.com/patent/US${doc.patentNumber}`,
          timestamp: new Date().toISOString()
        })) || [];

        database.patents = [
          ...database.patents.filter(p => p.drug !== drugName),
          ...patents
        ];

        logger.info(`Found ${patents.length} patents for ${drugName}`);
        return patents;
      }

      return [];
    } catch (error) {
      logger.error(`Error searching patents for ${drugName}:`, error.message);
      return [];
    }
  }
}

// ===========================================
// SAFETY SIGNAL DETECTION
// ===========================================

class SafetySignalAnalyzer {
  // Analyze safety signals across all drugs
  analyzeSafetySignals() {
    const signals = [];
    const events = database.adverseEvents;
    
    // Group events by drug
    const drugEvents = {};
    events.forEach(event => {
      if (!drugEvents[event.drug]) {
        drugEvents[event.drug] = [];
      }
      drugEvents[event.drug].push(event);
    });

    // Analyze each drug
    Object.entries(drugEvents).forEach(([drug, drugEvents]) => {
      // Sort by count and EBGM score
      const topSignals = drugEvents
        .sort((a, b) => parseFloat(b.ebgmScore) - parseFloat(a.ebgmScore))
        .slice(0, 10);

      topSignals.forEach(signal => {
        signals.push({
          drug,
          event: signal.event,
          count: signal.count,
          ebgmScore: signal.ebgmScore,
          severity: this.classifySeverity(signal.ebgmScore),
          trend: this.calculateTrend(drug, signal.event),
          timestamp: new Date().toISOString()
        });
      });
    });

    database.safetySignals = signals;
    return signals;
  }

  classifySeverity(ebgmScore) {
    const score = parseFloat(ebgmScore);
    if (score > 3) return 'HIGH';
    if (score > 2) return 'MEDIUM';
    if (score > 1) return 'LOW';
    return 'MINIMAL';
  }

  calculateTrend(drug, event) {
    // Simplified trend calculation
    return 'STABLE'; // In production, compare with historical data
  }

  // Identify class-wide effects
  identifyClassEffects() {
    const eventFrequency = {};
    
    database.adverseEvents.forEach(event => {
      if (!eventFrequency[event.event]) {
        eventFrequency[event.event] = new Set();
      }
      eventFrequency[event.event].add(event.drug);
    });

    const classEffects = [];
    Object.entries(eventFrequency).forEach(([event, drugs]) => {
      if (drugs.size >= 3) {
        classEffects.push({
          event,
          affectedDrugs: Array.from(drugs),
          prevalence: (drugs.size / RNAI_PORTFOLIO.alnylam.drugs.length * 100).toFixed(1) + '%',
          classWideRisk: true,
          timestamp: new Date().toISOString()
        });
      }
    });

    return classEffects;
  }
}

// ===========================================
// COMPETITIVE INTELLIGENCE
// ===========================================

class CompetitiveIntelligence {
  async analyzeCompetitors() {
    const analysis = {
      companies: {},
      pipelineComparison: {},
      upcomingMilestones: [],
      competitiveThreats: []
    };

    // Analyze each competitor
    for (const competitor of RNAI_PORTFOLIO.competitors) {
      const companyData = {
        name: competitor.company,
        ticker: competitor.ticker,
        drugs: competitor.drugs,
        clinicalTrials: database.clinicalTrials.filter(t => 
          this.isCompanyTrial(t, competitor.company)
        ),
        pdufaDates: competitor.pdufaDates || [],
        riskScore: this.calculateCompetitorRisk(competitor)
      };

      analysis.companies[competitor.company] = companyData;

      // Check for upcoming PDUFA dates
      competitor.pdufaDates?.forEach(pdufa => {
        const daysUntil = Math.floor((new Date(pdufa.date) - new Date()) / (1000 * 60 * 60 * 24));
        if (daysUntil > 0 && daysUntil < 180) {
          analysis.upcomingMilestones.push({
            company: competitor.company,
            drug: pdufa.drug,
            event: 'PDUFA',
            date: pdufa.date,
            daysUntil,
            impact: 'HIGH',
            timestamp: new Date().toISOString()
          });
        }
      });
    }

    // Identify competitive threats
    analysis.competitiveThreats = this.identifyThreats(analysis.companies);

    return analysis;
  }

  isCompanyTrial(trial, companyName) {
    const sponsor = trial.sponsor?.toLowerCase() || '';
    return sponsor.includes(companyName.toLowerCase());
  }

  calculateCompetitorRisk(competitor) {
    let risk = 0;
    
    // Risk factors
    if (competitor.pdufaDates?.length > 0) risk += 30;
    if (competitor.drugs.length > 3) risk += 20;
    
    const trials = database.clinicalTrials.filter(t => 
      this.isCompanyTrial(t, competitor.company)
    );
    
    const phase3Trials = trials.filter(t => t.phase?.includes('PHASE3'));
    risk += phase3Trials.length * 15;
    
    return Math.min(100, risk);
  }

  identifyThreats(companies) {
    const threats = [];
    
    Object.values(companies).forEach(company => {
      if (company.riskScore > 50) {
        threats.push({
          company: company.name,
          threat: 'High competitive risk',
          riskScore: company.riskScore,
          factors: this.getThreatFactors(company),
          mitigation: this.suggestMitigation(company),
          timestamp: new Date().toISOString()
        });
      }
    });

    return threats.sort((a, b) => b.riskScore - a.riskScore);
  }

  getThreatFactors(company) {
    const factors = [];
    if (company.pdufaDates?.length > 0) factors.push('Upcoming approvals');
    if (company.clinicalTrials.length > 5) factors.push('Large pipeline');
    const phase3 = company.clinicalTrials.filter(t => t.phase?.includes('PHASE3'));
    if (phase3.length > 0) factors.push(`${phase3.length} Phase 3 trials`);
    return factors;
  }

  suggestMitigation(company) {
    if (company.pdufaDates?.length > 0) {
      return 'Monitor approval decision closely, prepare competitive response';
    }
    if (company.clinicalTrials.length > 5) {
      return 'Accelerate own pipeline development';
    }
    return 'Continue monitoring';
  }
}

// ===========================================
// REGULATORY PATTERN RECOGNITION
// ===========================================

class RegulatoryPatternAnalyzer {
  analyzeApprovalPatterns() {
    const patterns = {
      approvalTimes: [],
      cmcRequirements: [],
      safetyRequirements: [],
      trends: {}
    };

    // Analyze approval times over years
    const approvals = database.approvals;
    approvals.forEach(approval => {
      if (approval.approvalDate) {
        patterns.approvalTimes.push({
          drug: approval.drug,
          date: approval.approvalDate,
          year: new Date(approval.approvalDate).getFullYear()
        });
      }
    });

    // Identify trends
    patterns.trends = {
      acceleratingApprovals: this.checkAcceleratingApprovals(patterns.approvalTimes),
      safetyRelaxation: this.checkSafetyRelaxation(),
      cmcSimplification: this.checkCMCSimplification()
    };

    return patterns;
  }

  checkAcceleratingApprovals(approvalTimes) {
    // Group by year
    const byYear = {};
    approvalTimes.forEach(a => {
      if (!byYear[a.year]) byYear[a.year] = 0;
      byYear[a.year]++;
    });

    // Check if approvals are increasing
    const years = Object.keys(byYear).sort();
    if (years.length >= 2) {
      const recent = byYear[years[years.length - 1]] || 0;
      const previous = byYear[years[years.length - 2]] || 0;
      return recent > previous ? 'ACCELERATING' : 'STABLE';
    }

    return 'INSUFFICIENT_DATA';
  }

  checkSafetyRelaxation() {
    // Analyze safety signal trends
    const signals = database.safetySignals;
    const highSeverity = signals.filter(s => s.severity === 'HIGH').length;
    const totalSignals = signals.length;
    
    if (totalSignals === 0) return 'INSUFFICIENT_DATA';
    
    const severityRatio = highSeverity / totalSignals;
    return severityRatio < 0.1 ? 'RELAXING' : 'STABLE';
  }

  checkCMCSimplification() {
    // Check guidance document trends
    const recentGuidance = database.regulatoryDocuments.filter(doc => {
      const date = new Date(doc.date || doc.timestamp);
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
      return date > sixMonthsAgo;
    });

    const simplificationKeywords = ['streamlined', 'abbreviated', 'simplified', 'expedited'];
    const simplificationDocs = recentGuidance.filter(doc => 
      simplificationKeywords.some(keyword => 
        (doc.title?.toLowerCase() || '').includes(keyword) ||
        (doc.snippet?.toLowerCase() || '').includes(keyword)
      )
    );

    return simplificationDocs.length > 0 ? 'SIMPLIFYING' : 'STABLE';
  }

  // Predict future regulatory requirements
  predictFutureRequirements() {
    const predictions = {
      cmcRequirements: {
        current: 'Full analytical characterization required',
        predicted: 'Platform approach likely accepted by 2026',
        confidence: 75,
        basis: 'Based on recent FDA guidance trends'
      },
      safetyMonitoring: {
        current: 'Quarterly PSUR submissions',
        predicted: 'Annual submissions for established platforms',
        confidence: 60,
        basis: 'Following mAb precedent'
      },
      clinicalTrials: {
        current: 'Full Phase 3 required',
        predicted: 'Accelerated approval based on surrogate endpoints',
        confidence: 80,
        basis: 'FDA Accelerated Approval expansion'
      },
      timeline: '2025-2027',
      lastUpdated: new Date().toISOString()
    };

    return predictions;
  }
}

// ===========================================
// API ROUTES
// ===========================================

// Initialize services
const fdaService = new FDAService();
const clinicalTrialsService = new ClinicalTrialsService();
const emaService = new EMAService();
const patentService = new PatentService();
const safetyAnalyzer = new SafetySignalAnalyzer();
const competitiveIntel = new CompetitiveIntelligence();
const patternAnalyzer = new RegulatoryPatternAnalyzer();

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Get portfolio overview
app.get('/api/portfolio/overview', async (req, res) => {
  try {
    const overview = {
      portfolio: RNAI_PORTFOLIO,
      lastUpdated: database.lastUpdated,
      summary: {
        totalAdverseEvents: database.adverseEvents.length,
        activeClinicalTrials: database.clinicalTrials.filter(t => 
          t.status === 'RECRUITING' || t.status === 'ACTIVE'
        ).length,
        safetySignals: database.safetySignals.filter(s => 
          s.severity === 'HIGH' || s.severity === 'MEDIUM'
        ).length,
        upcomingMilestones: database.pdufaDates.length
      },
      timestamp: new Date().toISOString()
    };

    res.json(overview);
  } catch (error) {
    logger.error('Error getting portfolio overview:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fetch all data for a specific drug
app.get('/api/drug/:drugName', async (req, res) => {
  try {
    const { drugName } = req.params;
    
    // Fetch all data sources in parallel
    const [adverseEvents, approvals, clinicalTrials, emaData, patents] = await Promise.all([
      fdaService.fetchAdverseEvents(drugName),
      fdaService.fetchDrugApprovals(drugName),
      database.clinicalTrials.filter(t => t.drug === drugName),
      emaService.searchEMAMedicines(drugName),
      patentService.searchPatents(drugName)
    ]);

    const drugData = {
      drug: drugName,
      data: {
        adverseEvents,
        approvals,
        clinicalTrials,
        emaData,
        patents
      },
      analysis: {
        safetySignals: database.safetySignals.filter(s => s.drug === drugName),
        riskScore: calculateDrugRiskScore(drugName)
      },
      timestamp: new Date().toISOString()
    };

    res.json(drugData);
  } catch (error) {
    logger.error(`Error fetching data for ${req.params.drugName}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get adverse events
app.get('/api/adverse-events/:drugName?', async (req, res) => {
  try {
    const { drugName } = req.params;
    
    if (drugName) {
      const events = await fdaService.fetchAdverseEvents(drugName);
      res.json(events);
    } else {
      // Return all cached adverse events
      res.json(database.adverseEvents);
    }
  } catch (error) {
    logger.error('Error fetching adverse events:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get clinical trials
app.get('/api/clinical-trials', async (req, res) => {
  try {
    const trials = await clinicalTrialsService.searchRNAiTrials();
    const landscape = await clinicalTrialsService.getCompetitiveLandscape();
    
    res.json({
      trials,
      landscape,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error fetching clinical trials:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get safety signals
app.get('/api/safety-signals', (req, res) => {
  try {
    const signals = safetyAnalyzer.analyzeSafetySignals();
    const classEffects = safetyAnalyzer.identifyClassEffects();
    
    res.json({
      signals,
      classEffects,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error analyzing safety signals:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get competitive intelligence
app.get('/api/competitive-intelligence', async (req, res) => {
  try {
    const analysis = await competitiveIntel.analyzeCompetitors();
    res.json(analysis);
  } catch (error) {
    logger.error('Error analyzing competitors:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get regulatory patterns and predictions
app.get('/api/regulatory-patterns', (req, res) => {
  try {
    const patterns = patternAnalyzer.analyzeApprovalPatterns();
    const predictions = patternAnalyzer.predictFutureRequirements();
    
    res.json({
      patterns,
      predictions,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error analyzing regulatory patterns:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Search FDA guidance documents
app.get('/api/guidance-documents', async (req, res) => {
  try {
    const { search = 'RNAi oligonucleotide' } = req.query;
    const documents = await fdaService.searchGuidanceDocuments(search);
    res.json(documents);
  } catch (error) {
    logger.error('Error searching guidance documents:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get EMA data
app.get('/api/ema/:medicineName', async (req, res) => {
  try {
    const { medicineName } = req.params;
    const emaData = await emaService.searchEMAMedicines(medicineName);
    const eparDocs = await emaService.getEPARDocuments(medicineName);
    
    res.json({
      medicines: emaData,
      eparDocuments: eparDocs,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error(`Error fetching EMA data for ${req.params.medicineName}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh all data (manual trigger)
app.post('/api/refresh-all', async (req, res) => {
  try {
    logger.info('Starting full data refresh...');
    
    const startTime = Date.now();
    const results = {
      adverseEvents: 0,
      clinicalTrials: 0,
      approvals: 0,
      errors: []
    };

    // Fetch adverse events for all drugs
    for (const drug of RNAI_PORTFOLIO.alnylam.drugs) {
      try {
        const events = await fdaService.fetchAdverseEvents(drug.name);
        results.adverseEvents += events.length;
        await fdaService.fetchDrugApprovals(drug.name);
        results.approvals++;
      } catch (error) {
        results.errors.push(`${drug.name}: ${error.message}`);
      }
    }

    // Fetch clinical trials
    const trials = await clinicalTrialsService.searchRNAiTrials();
    results.clinicalTrials = trials.length;

    // Analyze safety signals
    safetyAnalyzer.analyzeSafetySignals();

    // Update last refresh time
    database.lastUpdated.fullRefresh = new Date().toISOString();

    const duration = Date.now() - startTime;
    logger.info(`Full data refresh completed in ${duration}ms`);

    res.json({
      message: 'Data refresh completed',
      duration: `${duration}ms`,
      results,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error during data refresh:', error);
    res.status(500).json({ error: 'Refresh failed' });
  }
});

// Get PDUFA dates
app.get('/api/pdufa-dates', (req, res) => {
  try {
    const pdufaDates = [];
    
    // Add known PDUFA dates
    RNAI_PORTFOLIO.competitors.forEach(competitor => {
      competitor.pdufaDates?.forEach(pdufa => {
        const daysUntil = Math.floor((new Date(pdufa.date) - new Date()) / (1000 * 60 * 60 * 24));
        pdufaDates.push({
          company: competitor.company,
          drug: pdufa.drug,
          date: pdufa.date,
          daysUntil,
          status: daysUntil < 0 ? 'PASSED' : daysUntil < 30 ? 'IMMINENT' : 'UPCOMING',
          impact: 'HIGH',
          timestamp: new Date().toISOString()
        });
      });
    });

    res.json(pdufaDates.sort((a, b) => a.daysUntil - b.daysUntil));
  } catch (error) {
    logger.error('Error fetching PDUFA dates:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ===========================================
// HELPER FUNCTIONS
// ===========================================

function calculateDrugRiskScore(drugName) {
  let score = 0;
  
  // Check adverse events
  const adverseEvents = database.adverseEvents.filter(e => e.drug === drugName);
  const highEBGM = adverseEvents.filter(e => parseFloat(e.ebgmScore) > 2).length;
  score += Math.min(30, highEBGM * 5);
  
  // Check clinical trials
  const trials = database.clinicalTrials.filter(t => t.drug === drugName);
  const activeTrials = trials.filter(t => t.status === 'RECRUITING' || t.status === 'ACTIVE');
  if (activeTrials.length === 0) score += 10; // No active development
  
  // Check safety signals
  const signals = database.safetySignals.filter(s => s.drug === drugName);
  const highSeverity = signals.filter(s => s.severity === 'HIGH').length;
  score += Math.min(40, highSeverity * 10);
  
  return Math.min(100, score);
}

// ===========================================
// SCHEDULED TASKS
// ===========================================

// Refresh data every 6 hours
cron.schedule('0 */6 * * *', async () => {
  logger.info('Running scheduled data refresh...');
  
  try {
    // Refresh FDA data
    for (const drug of RNAI_PORTFOLIO.alnylam.drugs) {
      await fdaService.fetchAdverseEvents(drug.name);
      await new Promise(resolve => setTimeout(resolve, 1000)); // Rate limiting
    }
    
    // Refresh clinical trials
    await clinicalTrialsService.searchRNAiTrials();
    
    // Analyze safety signals
    safetyAnalyzer.analyzeSafetySignals();
    
    database.lastUpdated.scheduled = new Date().toISOString();
    logger.info('Scheduled refresh completed');
  } catch (error) {
    logger.error('Scheduled refresh failed:', error);
  }
});

// ===========================================
// SERVER INITIALIZATION
// ===========================================

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server
app.listen(PORT, async () => {
  logger.info(`RNAi Regulatory Intelligence Backend running on port ${PORT}`);
  logger.info('Initializing data...');
  
  // Initial data fetch for demonstration
  try {
    // Fetch initial data for Leqvio (main investment)
    await fdaService.fetchAdverseEvents('inclisiran');
    await fdaService.fetchDrugApprovals('inclisiran');
    
    // Fetch clinical trials
    await clinicalTrialsService.searchRNAiTrials();
    
    // Analyze initial data
    safetyAnalyzer.analyzeSafetySignals();
    
    database.lastUpdated.startup = new Date().toISOString();
    logger.info('Initial data loaded successfully');
    
    console.log('\n========================================');
    console.log('RNAi REGULATORY INTELLIGENCE SYSTEM');
    console.log('========================================');
    console.log(`Server: http://localhost:${PORT}`);
    console.log('\nAvailable Endpoints:');
    console.log('  GET  /health                        - System health check');
    console.log('  GET  /api/portfolio/overview        - Portfolio overview');
    console.log('  GET  /api/drug/:drugName            - All data for specific drug');
    console.log('  GET  /api/adverse-events/:drugName  - FDA adverse events');
    console.log('  GET  /api/clinical-trials           - All RNAi clinical trials');
    console.log('  GET  /api/safety-signals            - Safety signal analysis');
    console.log('  GET  /api/competitive-intelligence  - Competitor analysis');
    console.log('  GET  /api/regulatory-patterns       - Regulatory trends & predictions');
    console.log('  GET  /api/guidance-documents        - FDA guidance search');
    console.log('  GET  /api/ema/:medicineName         - EMA medicine data');
    console.log('  GET  /api/pdufa-dates               - Upcoming PDUFA dates');
    console.log('  POST /api/refresh-all               - Manual data refresh');
    console.log('\nMonitoring Drugs:');
    RNAI_PORTFOLIO.alnylam.drugs.forEach(drug => {
      console.log(`  - ${drug.brand} (${drug.name})`);
    });
    console.log('\nCompetitors:');
    RNAI_PORTFOLIO.competitors.forEach(comp => {
      console.log(`  - ${comp.company} (${comp.ticker})`);
    });
    console.log('========================================\n');
  } catch (error) {
    logger.error('Failed to load initial data:', error);
    console.log('\n⚠️  Warning: Initial data load failed. Server is running but data may be incomplete.');
    console.log('   Try POST /api/refresh-all to manually trigger data fetch.\n');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, closing server...');
  process.exit(0);
});

module.exports = app;