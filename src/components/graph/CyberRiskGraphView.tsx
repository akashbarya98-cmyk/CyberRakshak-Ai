import React, { useState, useRef, useEffect } from 'react';
import { 
  Search, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Globe, 
  Building2, 
  FileText, 
  AlertTriangle, 
  Radio, 
  Server,
  Info,
  ChevronRight,
  Plus,
  Sparkles,
  Link2,
  Move
} from 'lucide-react';
import { GraphNode, GraphLink, ViewMode } from '../../types';
import { INITIAL_GRAPH_NODES, INITIAL_GRAPH_LINKS } from '../../mock/initialData';

interface CyberRiskGraphViewProps {
  onAskCopilot?: (context: any) => void;
  onNavigate?: (view: ViewMode) => void;
  workspaceId?: string;
}

export const CyberRiskGraphView: React.FC<CyberRiskGraphViewProps> = ({
  onAskCopilot,
  onNavigate,
  workspaceId = 'ws-personal'
}) => {
  const [nodes, setNodes] = useState<GraphNode[]>(INITIAL_GRAPH_NODES);
  const [links, setLinks] = useState<GraphLink[]>(INITIAL_GRAPH_LINKS);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(INITIAL_GRAPH_NODES[0]);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('All Types');
  const [severityFilter, setSeverityFilter] = useState('All Severities');
  
  // Zoom & Pan state
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/risk-graph', {
      headers: { 'x-workspace-id': workspaceId }
    })
      .then(res => res.json())
      .then(data => {
        if (data && Array.isArray(data.nodes) && data.nodes.length > 0) {
          setNodes(data.nodes);
          setLinks(data.links || []);
          setSelectedNode(data.nodes[0]);
        }
      })
      .catch(() => {});
  }, [workspaceId]);

  // Add Node Modal state
  const [showAddModal, setShowAddModal] = useState(false);
  const [newLabel, setNewLabel] = useState('');
  const [newType, setNewType] = useState<GraphNode['type']>('Indicator');
  const [newRisk, setNewRisk] = useState<GraphNode['risk']>('High');
  const [linkTargetId, setLinkTargetId] = useState<string>('n-domain-1');
  const [isConfirmedLink, setIsConfirmedLink] = useState(false);
  const [newUncertainty, setNewUncertainty] = useState<any>('Medium (Heuristic Inference)');

  const svgRef = useRef<SVGSVGElement | null>(null);

  // Filter nodes based on user selections
  const filteredNodes = nodes.filter(n => {
    const matchesSearch = n.label.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          n.type.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = typeFilter === 'All Types' || n.type === typeFilter;
    const matchesSeverity = severityFilter === 'All Severities' || n.risk === severityFilter;
    return matchesSearch && matchesType && matchesSeverity;
  });

  const filteredNodeIds = new Set(filteredNodes.map(n => n.id));

  const filteredLinks = links.filter(l => 
    filteredNodeIds.has(l.source) && filteredNodeIds.has(l.target)
  );

  // Mouse / Pan / Drag interactions
  const handleCanvasMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    const targetTag = (e.target as HTMLElement).tagName.toLowerCase();
    if (targetTag === 'svg' || targetTag === 'rect') {
      setIsPanning(true);
      setPanStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
    }
  };

  const handleNodeMouseDown = (e: React.MouseEvent, nodeId: string) => {
    e.stopPropagation();
    setDraggingNodeId(nodeId);
    const node = nodes.find(n => n.id === nodeId);
    if (node) setSelectedNode(node);
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (draggingNodeId && svgRef.current) {
      const rect = svgRef.current.getBoundingClientRect();
      const x = (e.clientX - rect.left - panOffset.x) / zoomLevel;
      const y = (e.clientY - rect.top - panOffset.y) / zoomLevel;
      setNodes(prev => prev.map(n => n.id === draggingNodeId ? { ...n, x, y } : n));
    } else if (isPanning) {
      setPanOffset({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y
      });
    }
  };

  const handleMouseUp = () => {
    setDraggingNodeId(null);
    setIsPanning(false);
  };

  const resetView = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
  };

  const handleAddNode = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLabel.trim()) return;

    const id = `n-custom-${Date.now()}`;
    const newNode: GraphNode = {
      id,
      label: newLabel.trim(),
      type: newType,
      category: newType.toLowerCase() as any,
      risk: newRisk,
      x: 350 + (Math.random() * 80 - 40),
      y: 260 + (Math.random() * 80 - 40),
      details: {
        reputation: newRisk === 'High' || newRisk === 'Critical' ? 'Suspicious' : 'Neutral',
        relatedFindings: 1,
        firstSeen: 'Just now',
        source: 'Analyst Custom Entry',
        provenance: 'Manual Risk Modeling',
        observationTime: new Date().toLocaleTimeString(),
        uncertainty: newUncertainty,
        isDemo: false
      }
    };

    setNodes(prev => [...prev, newNode]);

    if (linkTargetId) {
      setLinks(prev => [
        ...prev,
        {
          source: id,
          target: linkTargetId,
          relation: isConfirmedLink ? 'Verified binding with' : 'Inferred association with',
          confirmed: isConfirmedLink,
          evidenceSource: 'Analyst Assessment',
          provenance: 'Manual Indicator Mapping',
          uncertainty: newUncertainty
        }
      ]);
    }

    setSelectedNode(newNode);
    setShowAddModal(false);
    setNewLabel('');
  };

  // Node Color Mapping
  const getNodeColor = (type: string, risk: string) => {
    switch (type) {
      case 'Domain': return { fill: '#1E40AF', stroke: '#60A5FA', glow: '#3B82F6' };
      case 'URL': return { fill: '#B45309', stroke: '#FBBF24', glow: '#F59E0B' };
      case 'Finding': return { fill: '#991B1B', stroke: '#F87171', glow: '#EF4444' };
      case 'Indicator': return { fill: '#0E7490', stroke: '#38BDF8', glow: '#06B6D4' };
      case 'Organization': return { fill: '#581C87', stroke: '#C084FC', glow: '#A855F7' };
      case 'Asset': return { fill: '#065F46', stroke: '#34D399', glow: '#10B981' };
      case 'Report': return { fill: '#6B21A8', stroke: '#E879F9', glow: '#D946EF' };
      default: return { fill: '#334155', stroke: '#94A3B8', glow: '#64748B' };
    }
  };

  return (
    <div className="space-y-4 max-w-7xl mx-auto pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight">
            Cyber Risk Graph
          </h2>
          <p className="text-xs text-[#667085] mt-0.5">
            Interactive evidence-relationship visualization correlating findings, indicators, organizations, and assets with strict provenance tracking.
          </p>
        </div>

        <button
          onClick={() => setShowAddModal(true)}
          className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-xs transition-colors self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Custom Indicator</span>
        </button>
      </div>

      {/* Main Visualizer Canvas & Details Panel Container */}
      <div className="bg-[#0B1120] border border-[#1E293B] rounded-2xl overflow-hidden shadow-xl flex flex-col lg:flex-row relative">
        
        {/* Left / Center: Interactive SVG Graph Area */}
        <div className="flex-1 flex flex-col relative h-[560px] lg:h-[620px]">
          
          {/* Top Controls Toolbar on Midnight Canvas */}
          <div className="p-3.5 border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md flex flex-wrap items-center justify-between gap-3 z-10">
            {/* Search Input */}
            <div className="relative min-w-[200px] flex-1 max-w-xs">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search nodes or types..."
                className="w-full pl-9 pr-3 py-1.5 bg-slate-800/80 border border-slate-700 rounded-lg text-xs text-white placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>

            {/* Filters */}
            <div className="flex items-center gap-2">
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none"
              >
                <option value="All Types">All Types</option>
                <option value="Domain">Domain</option>
                <option value="Finding">Finding</option>
                <option value="Indicator">Indicator</option>
                <option value="Organization">Organization</option>
                <option value="Asset">Asset</option>
                <option value="Report">Report</option>
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none"
              >
                <option value="All Severities">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>

              {/* Zoom & Pan Buttons */}
              <div className="flex items-center gap-1 bg-slate-800 border border-slate-700 rounded-lg p-0.5">
                <button
                  onClick={() => setZoomLevel(prev => Math.min(prev + 0.15, 1.8))}
                  className="p-1 text-slate-300 hover:text-white hover:bg-slate-700 rounded"
                  title="Zoom In"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setZoomLevel(prev => Math.max(prev - 0.15, 0.6))}
                  className="p-1 text-slate-300 hover:text-white hover:bg-slate-700 rounded"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={resetView}
                  className="p-1 text-slate-300 hover:text-white hover:bg-slate-700 rounded flex items-center gap-1 text-[10px]"
                  title="Reset Pan & Zoom"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Canvas SVG */}
          <div className="flex-1 w-full h-full relative cursor-grab active:cursor-grabbing overflow-hidden">
            <svg
              ref={svgRef}
              className="w-full h-full select-none"
              onMouseDown={handleCanvasMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
            >
              {/* Background Subtle Grid Pattern */}
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <circle cx="20" cy="20" r="1" fill="#1E293B" opacity="0.6" />
                </pattern>
                <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748B" />
                </marker>
                <marker id="arrow-inferred" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 1 L 10 5 L 0 9 z" fill="#D97706" />
                </marker>
              </defs>
              <rect width="100%" height="100%" fill="url(#grid)" />

              {/* Group with pan and zoom transform */}
              <g transform={`translate(${panOffset.x}, ${panOffset.y}) scale(${zoomLevel})`}>
                {/* Relationship Links */}
                {filteredLinks.map((link, idx) => {
                  const sourceNode = nodes.find(n => n.id === link.source);
                  const targetNode = nodes.find(n => n.id === link.target);
                  if (!sourceNode || !targetNode) return null;

                  const isSelectedLink = selectedNode && (selectedNode.id === sourceNode.id || selectedNode.id === targetNode.id);

                  return (
                    <g key={idx}>
                      <line
                        x1={sourceNode.x || 300}
                        y1={sourceNode.y || 250}
                        x2={targetNode.x || 400}
                        y2={targetNode.y || 250}
                        stroke={isSelectedLink ? (link.confirmed ? '#60A5FA' : '#FBBF24') : (link.confirmed ? '#334155' : '#78350F')}
                        strokeWidth={isSelectedLink ? 2.2 : (link.confirmed ? 1.5 : 1.2)}
                        strokeDasharray={link.confirmed ? 'none' : '5 4'}
                        strokeOpacity={isSelectedLink ? 0.95 : (link.confirmed ? 0.7 : 0.85)}
                        markerEnd={link.confirmed ? 'url(#arrow)' : 'url(#arrow-inferred)'}
                      />
                      <text
                        x={((sourceNode.x || 300) + (targetNode.x || 400)) / 2}
                        y={((sourceNode.y || 250) + (targetNode.y || 250)) / 2 - 5}
                        fill={link.confirmed ? '#94A3B8' : '#FBBF24'}
                        fontSize="9"
                        fontFamily="sans-serif"
                        textAnchor="middle"
                        className="pointer-events-none drop-shadow-xs"
                      >
                        {link.relation} {link.confirmed ? '' : '(inferred)'}
                      </text>
                    </g>
                  );
                })}

                {/* Graph Nodes */}
                {filteredNodes.map(node => {
                  const isSelected = selectedNode?.id === node.id;
                  const colors = getNodeColor(node.type, node.risk);

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${node.x || 350}, ${node.y || 250})`}
                      className="cursor-pointer"
                      onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
                    >
                      {/* Outer Glow Halo for Selected Node */}
                      {isSelected && (
                        <circle
                          r="32"
                          fill={colors.glow}
                          opacity="0.25"
                          className="animate-pulse"
                        />
                      )}

                      {/* Node Circle */}
                      <circle
                        r="22"
                        fill={colors.fill}
                        stroke={isSelected ? '#FFFFFF' : colors.stroke}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                        className="transition-transform hover:scale-110"
                      />

                      {/* Node Title / Label */}
                      <text
                        y="36"
                        fill="#F8FAFC"
                        fontSize="11"
                        fontWeight="bold"
                        textAnchor="middle"
                        className="pointer-events-none drop-shadow-sm"
                      >
                        {node.label}
                      </text>

                      {/* Node Subtitle Type */}
                      <text
                        y="48"
                        fill="#94A3B8"
                        fontSize="9"
                        textAnchor="middle"
                        className="pointer-events-none"
                      >
                        {node.type}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>

          {/* Bottom Graph Legend */}
          <div className="p-3 border-t border-slate-800 bg-slate-900/90 backdrop-blur-md flex flex-wrap items-center justify-between gap-4 text-[11px] text-slate-300">
            <div className="flex flex-wrap items-center gap-3">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-blue-600"></span> Domain
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> URL
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-600"></span> Finding
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-500"></span> Indicator
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-600"></span> Organization
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Asset
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-fuchsia-500"></span> Report
              </span>
            </div>

            <div className="flex items-center gap-4 text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-5 h-0.5 bg-slate-400"></span> Confirmed (Solid)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-5 h-0.5 border-t border-dashed border-amber-400"></span> Inferred (Dashed)
              </span>
            </div>
          </div>
        </div>

        {/* Right Side Panel: Node Details with Provenance & Uncertainty */}
        <div className="w-full lg:w-80 bg-slate-900 border-t lg:border-t-0 lg:border-l border-slate-800 p-5 flex flex-col justify-between text-slate-200">
          {selectedNode ? (
            <div className="space-y-4">
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Node Details & Provenance
                </h3>
                <div className="mt-2 flex items-center justify-between">
                  <h4 className="text-base font-bold text-white flex items-center gap-2 truncate">
                    <Globe className="w-4 h-4 text-blue-400 shrink-0" />
                    <span className="truncate">{selectedNode.label}</span>
                  </h4>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 shrink-0">
                    {selectedNode.type}
                  </span>
                </div>
                <div className="mt-1.5">
                  {selectedNode.details.isDemo ? (
                    <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                      Sample Demonstration Fixture
                    </span>
                  ) : (
                    <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      Live Verified Workspace Observation
                    </span>
                  )}
                </div>
              </div>

              {/* Rigorous Provenance & Technical Metadata */}
              <div className="space-y-2 text-xs bg-slate-800/60 p-3.5 rounded-xl border border-slate-700/60">
                <div className="flex justify-between">
                  <span className="text-slate-400">Reputation:</span>
                  <span className="font-semibold text-amber-400">{selectedNode.details.reputation || 'Active Node'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Evidence Source:</span>
                  <span className="font-semibold text-slate-200 text-right truncate max-w-[150px]">
                    {selectedNode.details.source || 'Direct Technical Sensor'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Provenance:</span>
                  <span className="font-semibold text-slate-200 text-right truncate max-w-[150px]">
                    {selectedNode.details.provenance || 'Passive Security Probe'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Observed At:</span>
                  <span className="font-semibold text-white">
                    {selectedNode.details.observationTime || selectedNode.details.firstSeen || 'Recent'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Uncertainty:</span>
                  <span className="font-semibold text-cyan-300">
                    {selectedNode.details.uncertainty || 'None (Direct Observation)'}
                  </span>
                </div>
              </div>

              {/* Connected Evidence Links */}
              <div className="space-y-2">
                <h5 className="text-xs font-bold text-slate-300">Connected Evidence Links:</h5>
                {(() => {
                  const connected = links.filter(l => l.source === selectedNode.id || l.target === selectedNode.id);
                  if (connected.length === 0) {
                    return <p className="text-[11px] text-slate-500">No active links attached.</p>;
                  }
                  return (
                    <ul className="text-xs space-y-1.5 text-slate-400 max-h-36 overflow-y-auto">
                      {connected.map((cl, cIdx) => {
                        const otherId = cl.source === selectedNode.id ? cl.target : cl.source;
                        const otherNode = nodes.find(n => n.id === otherId);
                        return (
                          <li key={cIdx} className="flex items-center justify-between gap-1 text-[11px] bg-slate-800/40 p-2 rounded-lg border border-slate-700/40">
                            <span className="truncate text-slate-300">
                              {cl.relation} &rarr; <strong className="text-white">{otherNode?.label || otherId}</strong>
                            </span>
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0 ${
                              cl.confirmed ? 'bg-blue-900/60 text-blue-300 border border-blue-700/60' : 'bg-amber-900/40 text-amber-300 border border-amber-700/40'
                            }`}>
                              {cl.confirmed ? 'Confirmed ✓' : 'Inferred ≈'}
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  );
                })()}
              </div>

              {/* Action Button: Ask AI Copilot about this node */}
              <div className="pt-2">
                <button
                  onClick={() => {
                    if (onAskCopilot) onAskCopilot(selectedNode);
                    if (onNavigate) onNavigate('copilot');
                  }}
                  className="w-full py-2.5 bg-purple-600 hover:bg-purple-700 text-white rounded-xl text-xs font-bold flex items-center justify-center gap-1.5 transition-colors shadow-sm"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Investigate with Copilot</span>
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 text-xs">
              Select any graph node to inspect evidence relationships.
            </div>
          )}

          <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-500 text-center">
            Evidence Provenance: SSRF Guard + DNS Pinning + Heuristics
          </div>
        </div>
      </div>

      {/* Modal: Add Custom Indicator Node */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 text-white border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="font-bold text-sm">Add Indicator to Cyber Risk Graph</h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleAddNode} className="space-y-3.5 text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 font-bold">Node Label / Identifier</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. rogue-kyc-verify.top or Telegram @recruiter_vip"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  className="w-full p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-bold">Entity Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value as any)}
                  className="w-full p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none"
                >
                  <option value="Indicator">Indicator (Phone / Handle / APK)</option>
                  <option value="Domain">Domain</option>
                  <option value="URL">URL</option>
                  <option value="Finding">Finding</option>
                  <option value="Organization">Organization</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-bold">Risk Severity</label>
                <select
                  value={newRisk}
                  onChange={(e) => setNewRisk(e.target.value as any)}
                  className="w-full p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-bold">Connect to Existing Node</label>
                <select
                  value={linkTargetId}
                  onChange={(e) => setLinkTargetId(e.target.value)}
                  className="w-full p-2.5 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none"
                >
                  {nodes.map(n => (
                    <option key={n.id} value={n.id}>{n.label} ({n.type})</option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="confirmCheck"
                  checked={isConfirmedLink}
                  onChange={(e) => setIsConfirmedLink(e.target.checked)}
                  className="rounded text-blue-600 focus:ring-blue-500 bg-slate-800 border-slate-700"
                />
                <label htmlFor="confirmCheck" className="text-slate-300">
                  Confirmed technical link (uncheck for inferred association)
                </label>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3.5 py-2 text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-bold"
                >
                  Add Node
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
