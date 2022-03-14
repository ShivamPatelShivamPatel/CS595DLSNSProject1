import networkx as nx
import pandas as pd

def main():
    g = nx.Graph()
    df = pd.read_csv("USMap.csv")
    g.add_nodes_from(df['state'].values)
    
    for borders in df['borders'].values:
        currentState = borders.split(":")[0]
        neighboringStates = [(currentState, neighbor) for neighbor in borders.split(":")[1:]]
        g.add_edges_from(neighboringStates)
    
    shortestPathMap = dict(nx.all_pairs_shortest_path_length(g))
    regions = {"MidWest":{"center":"WI","length":2},
               "NewEngland":{"center":"VT", "length":2},
               "South":{"center":"MS", "length":2},
               "West":{"center":"AZ", "length":1},
               "PacificNorthWest":{"center":"ID", "length":1}
               }

    optional_add = {
               "MidWest":"KS:WV",
               "NewEngland":"DE:MD",
               "South":"SC:FL:WV",
               "West":"CO",
               "PacificNorthWest":"HI"
               }


    optional_remove = {
               "MidWest":"KY",
               "NewEngland":"",
               "South":"",
               "West":"",
               "PacificNorthWest":""
               }

    # ../regionalCSVs/r.csv
    electionData = pd.read_csv("electionData.csv", index_col=False)
    for r in regions.keys():
        csv_name = "regionalCSVs/" + r + "/" + r + ".csv"
        regionMembers = list(
                            filter(lambda state: 
                                shortestPathMap[regions[r]["center"]][state] <= regions[r]["length"], shortestPathMap.keys()
                                )
                            )
        regionMembers += optional_add[r].split(":")
        regionMembers = list(set(regionMembers) - set(optional_remove[r].split(":")))
        
        regionalData = electionData[electionData.state.isin(regionMembers)]
        regionalData.to_csv(csv_name, index=False)
        
        print(regionalData.columns)
        print(electionData.columns)

if __name__ == main():
    main()
