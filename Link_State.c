#include <stdio.h>

#define INF 999

int main() {
    int n, start;
    int dist[10], visited[10] = {0};
    int cost[10][10];

    printf("Enter number of nodes: ");
    scanf("%d", &n);

    printf("Enter cost matrix (use 999 for no link):\n");

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            scanf("%d", &cost[i][j]);
        }
    }

    printf("Enter source node: ");
    scanf("%d", &start);

    // Initialize distances
    for (int i = 0; i < n; i++) {
        dist[i] = cost[start][i];
    }

    // Distance from source to itself is always 0
    dist[start] = 0;
    visited[start] = 1;

    // Dijkstra's algorithm
    for (int count = 0; count < n - 1; count++) {
        int min = INF;
        int next = -1;

        // Find unvisited node with minimum distance
        for (int i = 0; i < n; i++) {
            if (!visited[i] && dist[i] < min) {
                min = dist[i];
                next = i;
            }
        }

        // No reachable node remains
        if (next == -1)
            break;

        visited[next] = 1;

        // Relax adjacent nodes
        for (int i = 0; i < n; i++) {
            if (!visited[i] &&
                cost[next][i] != INF &&
                dist[next] + cost[next][i] < dist[i]) {

                dist[i] = dist[next] + cost[next][i];
            }
        }
    }

    printf("\nDestination\tCost\n");

    for (int i = 0; i < n; i++) {
        if (dist[i] == INF)
            printf("Node %d\t\tINF\n", i);
        else
            printf("Node %d\t\t%d\n", i, dist[i]);
    }

    return 0;
}

