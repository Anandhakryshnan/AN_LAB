#include <stdio.h>
#define INF 999

int main() {
    int n, start, dist[10], visited[10] = {0}, cost[10][10];

    printf("Enter number of nodes: ");
    scanf("%d", &n);

    printf("Enter cost matrix (use 999 for no link):\n");
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) 
            scanf("%d", &cost[i][j]);

    printf("Enter source node: ");
    scanf("%d", &start);

    for (int i = 0; i < n; i++) dist[i] = cost[start][i];
    visited[start] = 1;

    for (int count = 0; count < n - 1; count++) {
        int min = INF, next = -1;
        for (int i = 0; i < n; i++) {
            if (!visited[i] && dist[i] < min) {
                min = dist[i];
                next = i;
            }
        }
        if (next == -1) break;
        visited[next] = 1;

        for (int i = 0; i < n; i++) {
            if (dist[next] + cost[next][i] < dist[i]) {
                dist[i] = dist[next] + cost[next][i];
            }
        }
    }

    printf("\nDestination\tCost\n");
    for (int i = 0; i < n; i++) 
        printf("Node %d\t\t%d\n", i, dist[i]);

    return 0;
}
