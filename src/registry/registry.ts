import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = Node;

export type GetNodeRegistryBody = {
  nodes: Node[];
};

let nodesRegistry: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (req: Request, res: Response) => {
    res.send("live");
  });

  // Route for nodes to register themselves
  _registry.post("/registerNode", (req: Request<any, any, Node>, res: Response) => {
    const newNode: Node = req.body;

    // Validate node information (e.g., nodeId, pubKey)
    if (!newNode.nodeId || !newNode.pubKey) {
      return res.status(400).json({ error: "Invalid node information" });
    }

    // Check if the node is already registered
    const existingNode = nodesRegistry.find(node => node.nodeId === newNode.nodeId);
    if (existingNode) {
      return res.status(400).json({ error: "Node already registered" });
    }

    // Add the node to the registry
    nodesRegistry.push(newNode);

    // Send a success response
    return res.status(200).json({ message: "Node registered successfully", node: newNode });
  });


  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
