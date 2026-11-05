"""Exposure graph of Microsoft Security Exposure Management through advanced hunting.

Covers the graph tools of the Microsoft Sentinel MCP server (find_nodes, get_graph_context, find_blastradius,
find_walkable_paths, find_exposure_perimeter, find_connected_nodes) with two read tools on ExposureGraphNodes /
ExposureGraphEdges, using make-graph and graph-match as in Microsoft Learn 'Query the enterprise exposure graph'.
Needs read access to Exposure Management; the graph itself is computed by Microsoft (no extra cost)."""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from .. import kql
from ..errors import InputError
from ..graph.odata import clamp_int
from ..scopes import THREAT_HUNTING_READ
from ..util import gather_sections
from .common import MaxItems
from .registry import read_tool

MAX_HOPS = 4
# Node attributes used for filters and ranking. Criticality: Exposure Management criticality level, lower = more
# critical (Learn treats < 4 as a critical asset). The flags are present-or-absent properties in rawData.
_NODES = "\n".join([
    "let Nodes = ExposureGraphNodes",
    "| project NodeId, NodeName, NodeLabel, Categories,",
    "    Criticality = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel),",
    "    InternetFacing = isnotnull(NodeProperties.rawData.IsInternetFacing) or "
    "isnotnull(NodeProperties.rawData.exposedToInternet),",
    "    VulnerableToRCE = isnotnull(NodeProperties.rawData.vulnerableToRCE),",
    "    PrivilegeEscalation = isnotnull(NodeProperties.rawData.VulnerableToPrivilegeEscalation);",
])
SPEC_HELP = ("a node name or node ID, 'critical' (critical assets), 'internet' (internet-facing), 'rce' (vulnerable "
             "to remote code execution), 'label:<NodeLabel>' (e.g. 'label:ai-agent' for AI agents) or "
             "'category:<category>'; combine up to 3 with '+', e.g. 'category:device+critical'")
NodeSpec = Annotated[Optional[str], f"Node selector: {SPEC_HELP}."]
View = Literal["neighbors", "blast_radius", "perimeter", "paths"]


def condition(spec: str, var: str = "") -> str:
    """KQL condition for a node selector on a graph-match variable (var) or on the Nodes table (var='')."""
    terms = [t.strip() for t in str(spec or "").split("+") if t.strip()]
    if not terms or len(terms) > 3:
        raise InputError(f"Node selector must be {SPEC_HELP}.")
    p = f"{var}." if var else ""
    parts = []
    for term in terms:
        low = term.lower()
        if low == "critical":
            parts.append(f"(isnotnull({p}Criticality) and {p}Criticality < 4)")
        elif low in ("internet", "internet-facing", "internet_facing"):
            parts.append(f"{p}InternetFacing == true")
        elif low == "rce":
            parts.append(f"{p}VulnerableToRCE == true")
        elif low.startswith("label:"):
            parts.append(f"{p}NodeLabel =~ {kql.kql_str(term[6:], 'label', 200)}")
        elif low.startswith("category:"):
            # 'has' uses the index on the dynamic column, set_has_element makes the match exact (Learn tip)
            cat = kql.kql_str(term[9:].strip().lower(), "category", 100)
            parts.append(f"({p}Categories has {cat} and set_has_element({p}Categories, {cat}))")
        else:
            lit = kql.kql_str(term, "node", 300)
            fqdn = kql.kql_str(f"{term}.", "node", 301)   # device nodes can carry the FQDN
            parts.append(f"({p}NodeId == {lit} or {p}NodeName =~ {lit} or {p}NodeName startswith {fqdn})")
    return " and ".join(parts)


def _edge_filter(edge_labels: Optional[str]) -> Optional[str]:
    labels = [x.strip() for x in str(edge_labels or "").split(",") if x.strip()]
    if not labels:
        return None
    if len(labels) > 10:
        raise InputError("edge_labels takes at most 10 labels.")
    return f"| where EdgeLabel in~ ({', '.join(kql.kql_str(x, 'edge label', 100) for x in labels)})"


def _graph(edge_filter: Optional[str], hops: int, where: str, project: str) -> list[str]:
    return [x for x in [
        _NODES, "ExposureGraphEdges", edge_filter,
        "| make-graph SourceNodeId --> TargetNodeId with Nodes on NodeId",
        f"| graph-match cycles=none (s)-[e*1..{hops}]->(t)",
        f"    where {where}",
        f"    project {project}, EdgeLabels = map(e, EdgeLabel), Via = map(e, TargetNodeName)",
        "| extend Hops = array_length(EdgeLabels)",
    ] if x]


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Exposure graph: find nodes")
async def find_exposure_nodes(
    search: Annotated[Optional[str], "Part of the node name or the exact node ID."] = None,
    node_label: Annotated[Optional[str], "Only this node label, e.g. 'microsoft.compute/virtualmachines', 'user', "
                                         "'device'."] = None,
    category: Annotated[Optional[str], "Only this category, e.g. 'device', 'identity', 'virtual_machine', "
                                       "'ip_address'."] = None,
    critical_only: Annotated[bool, "Only critical assets (criticality level 0-3)."] = False,
    internet_facing_only: Annotated[bool, "Only internet-facing nodes."] = False,
    max_items: MaxItems = 50,
) -> dict:
    """Exposure graph of Microsoft Security Exposure Management (devices, identities, cloud resources, IPs and
    their relations). Without filters: the graph context - node labels with counts and critical assets, edge
    labels (relation types such as 'Can Authenticate As', 'routes traffic to') and categories, i.e. the values
    to use in explore_exposure_graph. With filters: matching nodes with label, categories, criticality (0 = very
    high ... 3 = low), internet exposure and RCE / privilege escalation flags, most critical first."""
    if not any([search, node_label, category, critical_only, internet_facing_only]):
        ok, errors = await gather_sections({
            "nodeLabels": kql.rows("ExposureGraphNodes\n| summarize Nodes = count(), Critical = countif("
                                   "toint(NodeProperties.rawData.criticalityLevel.criticalityLevel) < 4) by NodeLabel\n"
                                   "| order by Nodes desc\n| take 60"),
            "edgeLabels": kql.rows("ExposureGraphEdges\n| summarize Edges = count() by EdgeLabel\n"
                                   "| order by Edges desc\n| take 60"),
            "categories": kql.rows("ExposureGraphNodes\n| mv-expand Category = Categories to typeof(string)\n"
                                   "| summarize Nodes = count() by Category\n| order by Nodes desc\n| take 60"),
        })
        out: dict = {name: kql.shape_rows(rows, limit=60, max_str=200)[0] for name, rows in ok.items()}
        if errors:
            out["errors"] = errors
        out["hint"] = (f"explore_exposure_graph(view=..., source/target=...) takes a node selector: {SPEC_HELP}. "
                       "Use find_exposure_nodes(search=...) for exact node names.")
        return out
    filters = []
    if search:
        lit = kql.kql_str(search, "search", 300)
        filters.append(f"(NodeName contains {lit} or NodeId == {lit})")
    if node_label:
        filters.append(condition(f"label:{node_label}"))
    if category:
        filters.append(condition(f"category:{category}"))
    if critical_only:
        filters.append(condition("critical"))
    if internet_facing_only:
        filters.append(condition("internet"))
    query = "\n".join([_NODES, "Nodes", f"| where {' and '.join(filters)}",
                       "| order by Criticality asc nulls last, NodeName asc"])
    return await kql.hunt(query, max_items=max_items, max_str=400)


@read_tool(scopes=(THREAT_HUNTING_READ,), title="Exposure graph: blast radius, paths, perimeter")
async def explore_exposure_graph(
    view: Annotated[View, "neighbors: direct relations of one node (and its details); blast_radius: what an "
                          "attacker could reach from source (default targets: critical assets); perimeter: who/what "
                          "can reach target (internet-facing and RCE-vulnerable sources first); paths: paths "
                          "between source and target."],
    source: NodeSpec = None,
    target: NodeSpec = None,
    max_hops: Annotated[int, f"Maximum path length (1-{MAX_HOPS})."] = 3,
    edge_labels: Annotated[Optional[str], "Only follow these relation types, comma-separated, e.g. 'Can "
                                          "Authenticate As, CanRemoteInteractiveLogonTo'."] = None,
    max_items: MaxItems = 25,
) -> dict:
    """Attack-path analysis on the Exposure Management graph (replaces the Sentinel MCP graph tools
    find_blastradius, find_walkable_paths, find_exposure_perimeter, find_connected_nodes and get_graph_context).
    Results list the shortest path per reached node with the relation types (EdgeLabels) and intermediate nodes
    (Via), plus criticality and exposure flags; the KQL is included. Get node names, labels and categories from
    find_exposure_nodes first."""
    hops = clamp_int(max_hops, 1, MAX_HOPS, "max_hops")
    edge_filter = _edge_filter(edge_labels)
    if view == "neighbors":
        node = str(source or target or "").strip()
        if not node or any(c in node for c in ":+") or node.lower() in ("critical", "internet", "rce"):
            raise InputError("view='neighbors' needs one node name or node ID in source.")
        cond = condition(node)
        relations = "\n".join(x for x in [
            f"let N = ExposureGraphNodes | where {cond} | project NodeId;",
            "union",
            "  (ExposureGraphEdges | where SourceNodeId in (N) | project Direction = \"outgoing\", "
            "NodeName = SourceNodeName, EdgeLabel, OtherName = TargetNodeName, OtherLabel = TargetNodeLabel),",
            "  (ExposureGraphEdges | where TargetNodeId in (N) | project Direction = \"incoming\", "
            "NodeName = TargetNodeName, EdgeLabel, OtherName = SourceNodeName, OtherLabel = SourceNodeLabel)",
            edge_filter,
            "| summarize Count = count(), Examples = make_set(OtherName, 10) by NodeName, Direction, EdgeLabel, OtherLabel",
            "| order by Direction asc, Count desc"] if x)
        details = "\n".join(["ExposureGraphNodes", f"| where {cond}",
                             "| project NodeId, NodeName, NodeLabel, Categories, EntityIds, "
                             "Properties = NodeProperties.rawData", "| take 5"])
        ok, errors = await gather_sections({"node": kql.rows(details), "relations": kql.hunt(relations,
                                                                                               max_items=max_items)})
        out = {"view": view, "node": kql.shape_rows(ok.get("node") or [], limit=5, max_str=400)[0]}
        if "relations" in ok:
            out["relations"] = ok["relations"]
        if errors:
            out["errors"] = errors
        if "node" in ok and not ok["node"]:
            out["hint"] = "No node with this name or ID; use find_exposure_nodes(search=...)."
        return out
    if view == "blast_radius":
        if not source:
            raise InputError("view='blast_radius' needs source (the node assumed to be compromised).")
        tgt = target or "critical"
        lines = _graph(edge_filter, hops, f"{condition(source, 's')} and {condition(tgt, 't')}",
                       "TargetId = t.NodeId, TargetName = t.NodeName, TargetLabel = t.NodeLabel, "
                       "TargetCriticality = t.Criticality, TargetInternetFacing = t.InternetFacing")
        lines += ["| summarize Paths = count(), arg_min(Hops, EdgeLabels, Via) by TargetId, TargetName, TargetLabel, "
                  "TargetCriticality, TargetInternetFacing",
                  "| order by TargetCriticality asc nulls last, Hops asc, Paths desc"]
        meta = {"source": source, "targets": tgt}
    elif view == "perimeter":
        if not target:
            raise InputError("view='perimeter' needs target (the asset to protect).")
        where = condition(target, "t") + (f" and {condition(source, 's')}" if source else "")
        lines = _graph(edge_filter, hops, where,
                       "SourceId = s.NodeId, SourceName = s.NodeName, SourceLabel = s.NodeLabel, "
                       "SourceInternetFacing = s.InternetFacing, SourceRCE = s.VulnerableToRCE, TargetName = t.NodeName")
        lines += ["| summarize Paths = count(), arg_min(Hops, EdgeLabels, Via, TargetName) by SourceId, SourceName, "
                  "SourceLabel, SourceInternetFacing, SourceRCE",
                  "| order by SourceInternetFacing desc, SourceRCE desc, Hops asc"]
        meta = {"target": target, "sources": source or "any"}
    else:   # paths
        if not (source and target):
            raise InputError("view='paths' needs source and target.")
        lines = _graph(edge_filter, hops, f"{condition(source, 's')} and {condition(target, 't')}",
                       "SourceName = s.NodeName, SourceLabel = s.NodeLabel, TargetName = t.NodeName, "
                       "TargetLabel = t.NodeLabel, TargetCriticality = t.Criticality")
        lines += ["| order by Hops asc"]
        meta = {"source": source, "target": target}
    result = await kql.hunt("\n".join(lines), max_items=max_items, max_str=600, view=view, maxHops=hops, **meta)
    if not result.get("count"):
        result["hint"] = ("No path found. Check the node names with find_exposure_nodes, raise max_hops (up to "
                          f"{MAX_HOPS}) or remove edge_labels.")
    return result
