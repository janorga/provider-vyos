# Example about how to add Custom Crossplane RBAC

## Configure it

Example for accessing all resources under `firewall.vyos.crossplane.io` API Group.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  # "namespace" omitted since ClusterRoles are not namespaced
  name: firewall-clusterrole
rules:
- apiGroups:
  - firewall.vyos.crossplane.io
  #
  # at the HTTP level, the name of the resource for accessing Secret
  # objects is "secrets"
  resources: ["*"]
  verbs: ["*"]
```

1. Apply the ClusterRole to the `crossplane-system` namespace.

    ```bash
    kubectl apply -f provider-vyos/examples/rbac/firewall.yaml -n crossplane-system
    ```
2. Create a ClusterRoleBinding to the Crossplane Service Accout

    ```bash
    kubeclt create clusterrolebinding firewall-crossplane-binding --clusterrole firewall-clusterrole --serviceaccount crossplane-system:crossplane
    ```

## Test it

Test if the service account can access the `ruleset` resources:

```bash
kubectl auth can-i get ruleset --as=system:serviceaccount:crossplane-system:crossplane
```